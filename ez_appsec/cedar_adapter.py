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
from pathlib import Path
from typing import Any, Iterable, Mapping


ENGINE_VERSION = "0.1.0"
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
CATEGORIES = ("secrets", "sast", "iac", "cve", "dependency_scanning", "other")
MAX_REQUEST_BYTES = 1024 * 1024
MAX_BINARY_BYTES = 128 * 1024 * 1024
PIN_PATTERN = re.compile(r"^[0-9a-f]{64}$")


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
