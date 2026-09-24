"""Optional consumer adapter for the standalone SourceBastion policy engine.

This module does not implement Cedar. It normalizes a *complete* in-memory
finding snapshot at the same point as PLAN-09, then invokes a pinned local
engine binary. The engine's policy provenance is still the caller's concern.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


ENGINE_VERSION = "0.1.0"
ENGINE_VERSION_V2 = "0.2.0"
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
CATEGORIES = ("secrets", "sast", "iac", "cve", "dependency_scanning", "other")
V2_CATEGORIES = ("secrets", "sast", "iac", "cve", "dependency_scanning", "container_images", "other")
MAX_REQUEST_BYTES = 1024 * 1024
MAX_BINARY_BYTES = 128 * 1024 * 1024
PIN_PATTERN = re.compile(r"^[0-9a-f]{64}$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class TrustedBaseline:
    """Caller-verified baseline identity and current finding IDs.

    This type is an explicit trust boundary, not proof of verification. CI or
    the hosted consumer must authenticate the protected ref or prior complete
    scan before constructing it. A fetch error must never become kind=none.
    """

    kind: str
    digest: str | None
    finding_ids: frozenset[str]


def _v2_category(finding: Mapping[str, Any]) -> str:
    """Map known scanner output categories; image origin takes precedence."""
    value = str(finding.get("category") or finding.get("type") or "").strip().lower()
    if value in {"container_scanning", "container", "container_images", "image"}:
        return "container_images"
    if value in {"hardcoded-secret", "secret", "secrets"}:
        return "secrets"
    if value in {"dependency", "dependencies", "dependency_scanning"}:
        return "dependency_scanning"
    if value in {"vulnerability", "vulnerabilities", "cve"}:
        return "cve"
    if value in V2_CATEGORIES:
        return value
    scanner = str(finding.get("scanner") or "").strip().lower()
    if scanner == "gitleaks":
        return "secrets"
    if scanner in {"semgrep", "php-vuln-scanner"}:
        return "sast"
    if scanner == "kics":
        return "iac"
    return "other"


def snapshot_v2_from_findings(
    findings: Iterable[Mapping[str, Any]], *, baseline: TrustedBaseline
) -> dict[str, Any]:
    """Build the complete post-ignore category/cohort snapshot for v2.

    No display severity filter belongs here. Raw findings stay on the consumer
    side; only counts and the authenticated baseline identity cross to Cedar.
    """
    if not isinstance(baseline, TrustedBaseline):
        raise ValueError("verified baseline is required")
    if not isinstance(baseline.finding_ids, frozenset) or any(
        not isinstance(value, str) or not value for value in baseline.finding_ids
    ):
        raise ValueError("baseline finding IDs must be non-empty strings")
    if baseline.kind == "none":
        if baseline.digest is not None or baseline.finding_ids:
            raise ValueError("first baseline cannot have prior findings")
    elif baseline.kind in {"target_ref", "prior_ref"}:
        if not isinstance(baseline.digest, str) or not DIGEST_PATTERN.fullmatch(baseline.digest):
            raise ValueError("baseline digest is required")
    else:
        raise ValueError("unknown baseline kind")
    counts = {
        category: {cohort: {level: 0 for level in SEVERITIES} for cohort in ("new", "existing")}
        for category in V2_CATEGORIES
    }
    seen: set[str] = set()
    for finding in findings:
        if not isinstance(finding, Mapping):
            raise ValueError("finding is not a mapping")
        finding_id = finding.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id or finding_id in seen:
            raise ValueError("finding IDs must be unique non-empty strings")
        seen.add(finding_id)
        category = _v2_category(finding)
        cohort = "existing" if finding_id in baseline.finding_ids else "new"
        counts[category][cohort][_severity(finding)] += 1
    snapshot = {
        "kind": "full", "complete": True, "suppression_basis": "post-ignore",
        "baseline": {"kind": baseline.kind, "digest": baseline.digest},
        "finding_count": len(seen), "by_category": counts,
    }
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    snapshot["digest"] = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return snapshot


def _error(code: str) -> dict[str, Any]:
    return {"status": "error", "diagnostic_codes": [code], "determining_policy_ids": [],
            "warning_policy_ids": [], "engine_version": None, "bundle_digest": None,
            "snapshot_digest": None}


def _severity(finding: Mapping[str, Any]) -> str:
    value = str(finding.get("severity") or "").lower()
    return value if value in SEVERITIES else "unknown"


def _category(finding: Mapping[str, Any]) -> str:
    value = str(finding.get("category") or finding.get("type") or finding.get("scanner") or "").lower()
    return value if value in CATEGORIES else "other"


def snapshot_from_findings(findings: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Build the fixed-vocabulary post-suppression, pre-display-filter summary."""
    severity = {key: 0 for key in SEVERITIES}
    category = {key: 0 for key in CATEGORIES}
    by_category = {cat: {level: 0 for level in SEVERITIES} for cat in CATEGORIES}
    finding_count = 0
    for finding in findings:
        if not isinstance(finding, Mapping):
            raise ValueError("finding is not a mapping")
        level, cat = _severity(finding), _category(finding)
        finding_count += 1
        severity[level] += 1
        category[cat] += 1
        by_category[cat][level] += 1
    snapshot = {
        "kind": "full", "complete": True, "suppression_basis": "post-ignore",
        "finding_count": finding_count, "severity": severity,
        "category": category, "by_category": by_category,
    }
    # The contract's RFC 8785 subset contains only ASCII keys, booleans and
    # non-negative integers, for which this is the same canonical byte string.
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    snapshot["digest"] = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return snapshot


def _binary_matches_pin(path: Path, expected_sha256: str) -> bool:
    if not PIN_PATTERN.fullmatch(expected_sha256):
        return False
    try:
        if not path.is_file() or path.stat().st_size > MAX_BINARY_BYTES:
            return False
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest() == expected_sha256
    except OSError:
        return False


def evaluate_cedar(
    findings: Iterable[Mapping[str, Any]], *, bundle_path: str | None,
    binary_path: str | None, binary_sha256: str | None,
) -> dict[str, Any]:
    """Invoke the pinned offline binary and verify result/exit-code agreement."""
    try:
        snapshot = snapshot_from_findings(findings)
    except (ValueError, TypeError, OverflowError):
        return _error("INVALID_SNAPSHOT")
    if not bundle_path or not binary_path or not binary_sha256:
        return _error("MISSING_CEDAR_CONFIGURATION")
    if not _binary_matches_pin(Path(binary_path), binary_sha256):
        return _error("BINARY_PIN_MISMATCH")
    try:
        with Path(bundle_path).open("rb") as handle:
            bundle_bytes = handle.read(MAX_REQUEST_BYTES + 1)
        if len(bundle_bytes) > MAX_REQUEST_BYTES:
            return _error("RESOURCE_LIMIT")
        bundle_data = json.loads(bundle_bytes)
        if not isinstance(bundle_data, dict) or set(bundle_data) != {"bundles"}:
            return _error("INVALID_BUNDLE_FILE")
        request = {"protocol_version": 1, "schema_version": 1, "profile": "scan-gate.v1",
                   "snapshot": snapshot, "bundles": bundle_data["bundles"]}
        input_bytes = json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(input_bytes) > MAX_REQUEST_BYTES:
            return _error("RESOURCE_LIMIT")
        completed = subprocess.run(
            [binary_path, "evaluate"], input=input_bytes, capture_output=True,
            timeout=8, check=False,
        )
        if len(completed.stdout) > 64 * 1024:
            return _error("INVALID_ENGINE_RESULT")
        result = json.loads(completed.stdout)
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        return _error("ENGINE_UNAVAILABLE")
    if not isinstance(result, dict):
        return _error("INVALID_ENGINE_RESULT")
    status = result.get("status")
    expected_code = {"passed": 0, "failed": 1, "error": 2}.get(status)
    if (expected_code is None or completed.returncode != expected_code
            or result.get("protocol_version") != 1
            or result.get("profile") != "scan-gate.v1"
            or result.get("schema_version") != 1
            or result.get("engine_version") != ENGINE_VERSION
            or result.get("snapshot_digest") != snapshot["digest"]):
        return _error("INVALID_ENGINE_RESULT")
    return result


def evaluate_cedar_v2(
    findings: Iterable[Mapping[str, Any]], *, baseline: TrustedBaseline,
    bundle_path: str | None, binary_path: str | None, binary_sha256: str | None,
) -> dict[str, Any]:
    """Invoke the pinned v2 engine over a caller-verified complete snapshot."""
    try:
        snapshot = snapshot_v2_from_findings(findings, baseline=baseline)
    except (ValueError, TypeError, OverflowError):
        return _error("INVALID_SNAPSHOT")
    if not bundle_path or not binary_path or not binary_sha256:
        return _error("MISSING_CEDAR_CONFIGURATION")
    if not _binary_matches_pin(Path(binary_path), binary_sha256):
        return _error("BINARY_PIN_MISMATCH")
    try:
        with Path(bundle_path).open("rb") as handle:
            bundle_bytes = handle.read(MAX_REQUEST_BYTES + 1)
        if len(bundle_bytes) > MAX_REQUEST_BYTES:
            return _error("RESOURCE_LIMIT")
        bundle_data = json.loads(bundle_bytes)
        if not isinstance(bundle_data, dict) or set(bundle_data) != {"bundles"}:
            return _error("INVALID_BUNDLE_FILE")
        request = {
            "protocol_version": 1, "schema_version": 2, "profile": "scan-gate.v2",
            "snapshot": snapshot, "bundles": bundle_data["bundles"],
        }
        input_bytes = json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(input_bytes) > MAX_REQUEST_BYTES:
            return _error("RESOURCE_LIMIT")
        completed = subprocess.run(
            [binary_path, "evaluate"], input=input_bytes, capture_output=True,
            timeout=8, check=False,
        )
        if len(completed.stdout) > 64 * 1024:
            return _error("INVALID_ENGINE_RESULT")
        result = json.loads(completed.stdout)
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        return _error("ENGINE_UNAVAILABLE")
    if not isinstance(result, dict):
        return _error("INVALID_ENGINE_RESULT")
    expected_code = {"passed": 0, "failed": 1, "error": 2}.get(result.get("status"))
    if (expected_code is None or completed.returncode != expected_code
            or result.get("protocol_version") != 1
            or result.get("profile") != "scan-gate.v2"
            or result.get("schema_version") != 2
            or result.get("engine_version") != ENGINE_VERSION_V2
            or result.get("snapshot_digest") != snapshot["digest"]):
        return _error("INVALID_ENGINE_RESULT")
    return result


def parity_result(findings: list[Mapping[str, Any]], rules: list[Any], cedar: Mapping[str, Any]) -> dict[str, Any]:
    """Compare rule-index identities and warnings without altering legacy enforcement."""
    legacy_fail_ids = []
    legacy_warning_ids = []
    for index, rule in enumerate(rules, 1):
        if rule.action == "ignore" or rule.evaluate(findings) is None:
            continue
        policy_id = f"plan09/plan09_rule_{index:04}"
        if rule.action == "fail":
            legacy_fail_ids.append(policy_id)
        elif rule.action == "warn":
            legacy_warning_ids.append(policy_id)
    expected_status = "failed" if legacy_fail_ids else "passed"
    actual_fail_ids = cedar.get("determining_policy_ids")
    actual_warning_ids = cedar.get("warning_policy_ids")
    mismatch = (cedar.get("status") != expected_status
                or actual_fail_ids != legacy_fail_ids
                or actual_warning_ids != legacy_warning_ids)
    return {"legacy_status": expected_status, "legacy_fail_ids": legacy_fail_ids,
            "legacy_warning_ids": legacy_warning_ids, "mismatch": mismatch}
