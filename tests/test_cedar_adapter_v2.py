"""M043 complete category/cohort snapshot conformance for the standalone engine."""

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from ez_appsec.cedar_adapter import (
    ENGINE_VERSION_V2,
    MAX_REQUEST_BYTES,
    TrustedBaseline,
    V2_CATEGORIES,
    evaluate_cedar_v2,
    snapshot_v2_from_findings,
)


def _baseline(*ids):
    return TrustedBaseline(
        kind="target_ref", digest="sha256:" + "a" * 64, finding_ids=frozenset(ids)
    )


def test_all_categories_cohorts_and_image_origin_are_complete():
    findings = [
        {"finding_id": "s1", "severity": "critical", "category": "hardcoded-secret", "secret": "private"},
        {"finding_id": "d1", "severity": "high", "category": "dependency", "scanner": "grype"},
        {"finding_id": "i1", "severity": "high", "category": "container_scanning", "scanner": "grype"},
        {"finding_id": "x1", "severity": "low", "category": "unknown-tool"},
    ]
    snapshot = snapshot_v2_from_findings(findings, baseline=_baseline("d1", "i1"))
    assert set(snapshot["by_category"]) == set(V2_CATEGORIES)
    assert snapshot["finding_count"] == 4
    assert snapshot["by_category"]["secrets"]["new"]["critical"] == 1
    assert snapshot["by_category"]["dependency_scanning"]["existing"]["high"] == 1
    assert snapshot["by_category"]["container_images"]["existing"]["high"] == 1
    assert snapshot["by_category"]["other"]["new"]["low"] == 1
    serialized = json.dumps(snapshot)
    assert "private" not in serialized
    without_digest = {key: value for key, value in snapshot.items() if key != "digest"}
    canonical = json.dumps(without_digest, sort_keys=True, separators=(",", ":"))
    assert snapshot["digest"] == "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def test_first_scan_counts_everything_new_and_invalid_baseline_fails_closed():
    first = TrustedBaseline(kind="none", digest=None, finding_ids=frozenset())
    snapshot = snapshot_v2_from_findings(
        [{"finding_id": "f1", "category": "sast", "severity": "medium"}], baseline=first
    )
    assert snapshot["by_category"]["sast"]["new"]["medium"] == 1
    assert snapshot["by_category"]["sast"]["existing"]["medium"] == 0
    with pytest.raises(ValueError):
        snapshot_v2_from_findings([], baseline=None)
    with pytest.raises(ValueError):
        snapshot_v2_from_findings([], baseline=TrustedBaseline("none", None, frozenset({"old"})))
    with pytest.raises(ValueError):
        snapshot_v2_from_findings([], baseline=TrustedBaseline("target_ref", None, frozenset()))
    with pytest.raises(ValueError):
        snapshot_v2_from_findings(
            [{"finding_id": "same"}, {"finding_id": "same"}], baseline=first
        )


@pytest.mark.parametrize(
    "category,expected",
    [
        ("hardcoded_secret", "secrets"),
        ("secret_detection", "secrets"),
        ("secret-scanning", "secrets"),
        ("static-analysis", "sast"),
        ("infrastructure-as-code", "iac"),
        ("dependency-scanning", "dependency_scanning"),
        ("container-scanning", "container_images"),
        ("container_images", "container_images"),
    ],
)
def test_v2_explicit_category_aliases_match_hosted_persistence(category, expected):
    snapshot = snapshot_v2_from_findings(
        [{"finding_id": "one", "category": category, "severity": " HIGH "}],
        baseline=TrustedBaseline("none", None, frozenset()),
    )
    assert snapshot["by_category"][expected]["new"]["high"] == 1


def test_v2_unknown_scanner_label_cannot_assert_a_gate_category():
    snapshot = snapshot_v2_from_findings(
        [{"finding_id": "one", "category": "unmapped-tool", "scanner": "gitleaks",
          "severity": "low"}],
        baseline=TrustedBaseline("none", None, frozenset()),
    )
    assert snapshot["by_category"]["other"]["new"]["low"] == 1
    assert snapshot["by_category"]["secrets"]["new"]["low"] == 0


def test_v2_cve_metadata_promotes_only_unknown_category():
    findings = [
        {"finding_id": "one", "category": "vulnerability", "cve": "CVE-2026-1234"},
        {"finding_id": "two", "category": "sast", "cve": "CVE-2026-5678"},
        {"finding_id": "three", "category": "cve"},
    ]
    snapshot = snapshot_v2_from_findings(
        findings, baseline=TrustedBaseline("none", None, frozenset()),
    )
    assert snapshot["by_category"]["cve"]["new"]["unknown"] == 1
    assert snapshot["by_category"]["sast"]["new"]["unknown"] == 1
    assert snapshot["by_category"]["other"]["new"]["unknown"] == 1


def test_missing_v2_binary_is_non_green():
    result = evaluate_cedar_v2(
        [], baseline=_baseline(), bundle_path=None, binary_path=None, binary_sha256=None
    )
    assert result["status"] == "error"
    assert result["diagnostic_codes"] == ["MISSING_CEDAR_CONFIGURATION"]


def _pinned_engine(tmp_path):
    binary = tmp_path / "engine"
    binary.write_bytes(b"fake-engine-bytes")
    pin = hashlib.sha256(binary.read_bytes()).hexdigest()
    return binary, pin


def _bundle(tmp_path, value='{"bundles":[]}'):
    bundle = tmp_path / "bundle.json"
    bundle.write_text(value, encoding="utf-8")
    return bundle


def test_v2_rejects_a_binary_that_does_not_match_its_pin(tmp_path):
    binary, _ = _pinned_engine(tmp_path)
    result = evaluate_cedar_v2(
        [], baseline=_baseline(), bundle_path=str(_bundle(tmp_path)),
        binary_path=str(binary), binary_sha256="0" * 64,
    )

    assert result["status"] == "error"
    assert result["diagnostic_codes"] == ["BINARY_PIN_MISMATCH"]


@pytest.mark.parametrize(
    "payload",
    [b"not-json", b"[]", b"{}", json.dumps({"status": "unexpected"}).encode("ascii")],
    ids=["not-json", "not-object", "empty-object", "unknown-status"],
)
def test_v2_rejects_malformed_engine_output(tmp_path, monkeypatch, payload):
    binary, pin = _pinned_engine(tmp_path)
    monkeypatch.setattr(
        "ez_appsec.cedar_adapter.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [str(binary), "evaluate"], 0, stdout=payload, stderr=b""
        ),
    )

    result = evaluate_cedar_v2(
        [], baseline=_baseline(), bundle_path=str(_bundle(tmp_path)),
        binary_path=str(binary), binary_sha256=pin,
    )

    assert result["status"] == "error"
    assert result["diagnostic_codes"] == ["INVALID_ENGINE_RESULT"]


def test_v2_accepts_a_fully_valid_engine_response(tmp_path, monkeypatch):
    binary, pin = _pinned_engine(tmp_path)
    snapshot = snapshot_v2_from_findings([], baseline=_baseline())
    engine_result = {
        "status": "passed",
        "protocol_version": 1,
        "profile": "scan-gate.v2",
        "schema_version": 2,
        "engine_version": ENGINE_VERSION_V2,
        "snapshot_digest": snapshot["digest"],
        "determining_policy_ids": [],
        "warning_policy_ids": [],
    }
    monkeypatch.setattr(
        "ez_appsec.cedar_adapter.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [str(binary), "evaluate"], 0,
            stdout=json.dumps(engine_result).encode("utf-8"), stderr=b"",
        ),
    )

    result = evaluate_cedar_v2(
        [], baseline=_baseline(), bundle_path=str(_bundle(tmp_path)),
        binary_path=str(binary), binary_sha256=pin,
    )

    assert result == engine_result


@pytest.mark.parametrize(
    ("return_code", "overrides"),
    [
        (1, {"status": "passed"}),
        (0, {"status": "failed"}),
        (0, {"protocol_version": 2}),
        (0, {"profile": "scan-gate.v1"}),
        (0, {"schema_version": 1}),
        (0, {"engine_version": "0.1.0"}),
        (0, {"snapshot_digest": "sha256:" + "b" * 64}),
    ],
    ids=[
        "failed-exit-code", "passed-exit-code", "protocol", "profile", "schema",
        "engine-version", "snapshot-digest",
    ],
)
def test_v2_rejects_protocol_and_exit_code_mismatches(
    tmp_path, monkeypatch, return_code, overrides
):
    binary, pin = _pinned_engine(tmp_path)
    snapshot = snapshot_v2_from_findings([], baseline=_baseline())
    engine_result = {
        "status": "passed", "protocol_version": 1, "profile": "scan-gate.v2",
        "schema_version": 2, "engine_version": ENGINE_VERSION_V2,
        "snapshot_digest": snapshot["digest"], "determining_policy_ids": [],
        "warning_policy_ids": [],
    }
    engine_result.update(overrides)
    monkeypatch.setattr(
        "ez_appsec.cedar_adapter.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [str(binary), "evaluate"], return_code,
            stdout=json.dumps(engine_result).encode("utf-8"), stderr=b"",
        ),
    )

    result = evaluate_cedar_v2(
        [], baseline=_baseline(), bundle_path=str(_bundle(tmp_path)),
        binary_path=str(binary), binary_sha256=pin,
    )

    assert result["status"] == "error"
    assert result["diagnostic_codes"] == ["INVALID_ENGINE_RESULT"]


@pytest.mark.parametrize(
    ("bundle_value", "expected_code"),
    [
        ("not-json", "ENGINE_UNAVAILABLE"),
        ('{"other":[]}', "INVALID_BUNDLE_FILE"),
        ('{"bundles":[],"extra":false}', "INVALID_BUNDLE_FILE"),
    ],
    ids=["invalid-json", "missing-bundles", "extra-key"],
)
def test_v2_rejects_malformed_bundles(tmp_path, monkeypatch, bundle_value, expected_code):
    binary, pin = _pinned_engine(tmp_path)
    executed = False

    def fail_if_run(*_args, **_kwargs):
        nonlocal executed
        executed = True
        raise AssertionError("engine must not run for a malformed bundle")

    monkeypatch.setattr("ez_appsec.cedar_adapter.subprocess.run", fail_if_run)
    result = evaluate_cedar_v2(
        [], baseline=_baseline(), bundle_path=str(_bundle(tmp_path, bundle_value)),
        binary_path=str(binary), binary_sha256=pin,
    )

    assert executed is False
    assert result["status"] == "error"
    assert result["diagnostic_codes"] == [expected_code]


def test_v2_enforces_bundle_request_and_output_limits(tmp_path, monkeypatch):
    binary, pin = _pinned_engine(tmp_path)
    oversized_bundle = '{"bundles":"' + "x" * (MAX_REQUEST_BYTES + 1) + '"}'
    result = evaluate_cedar_v2(
        [], baseline=_baseline(), bundle_path=str(_bundle(tmp_path, oversized_bundle)),
        binary_path=str(binary), binary_sha256=pin,
    )
    assert result["diagnostic_codes"] == ["RESOURCE_LIMIT"]

    # This bundle fits, while adding the complete fixed-vocabulary snapshot
    # exceeds the request limit.
    large_bundle = '{"bundles":"' + "x" * (MAX_REQUEST_BYTES - 100) + '"}'
    result = evaluate_cedar_v2(
        [], baseline=_baseline(), bundle_path=str(_bundle(tmp_path, large_bundle)),
        binary_path=str(binary), binary_sha256=pin,
    )
    assert result["diagnostic_codes"] == ["RESOURCE_LIMIT"]

    monkeypatch.setattr(
        "ez_appsec.cedar_adapter.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [str(binary), "evaluate"], 0, stdout=b"x" * (64 * 1024 + 1), stderr=b""
        ),
    )
    result = evaluate_cedar_v2(
        [], baseline=_baseline(), bundle_path=str(_bundle(tmp_path)),
        binary_path=str(binary), binary_sha256=pin,
    )
    assert result["status"] == "error"
    assert result["diagnostic_codes"] == ["INVALID_ENGINE_RESULT"]


def test_v2_enforces_the_execution_timeout(tmp_path, monkeypatch):
    binary, pin = _pinned_engine(tmp_path)

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired([str(binary), "evaluate"], timeout=8)

    monkeypatch.setattr("ez_appsec.cedar_adapter.subprocess.run", timeout)
    result = evaluate_cedar_v2(
        [], baseline=_baseline(), bundle_path=str(_bundle(tmp_path)),
        binary_path=str(binary), binary_sha256=pin,
    )

    assert result["status"] == "error"
    assert result["diagnostic_codes"] == ["ENGINE_UNAVAILABLE"]


@pytest.mark.integration
def test_v2_request_matches_live_engine_if_configured(tmp_path):
    binary = os.getenv("SOURCEBASTION_POLICY_ENGINE_V2_BINARY")
    if not binary:
        pytest.skip("set SOURCEBASTION_POLICY_ENGINE_V2_BINARY for v2 live proof")
    binary_path = Path(binary)
    pin = hashlib.sha256(binary_path.read_bytes()).hexdigest()
    settings = {
        "version": 1,
        "minimum_severity": "high",
        "categories": {
            category: {"enabled": True, "max_new": 0, "max_existing": 0}
            for category in V2_CATEGORIES
        },
    }
    compiled = subprocess.run(
        [binary, "compile-gate"], input=json.dumps(settings).encode(),
        capture_output=True, check=True,
    )
    bundle = tmp_path / "gate-bundle.json"
    bundle.write_bytes(compiled.stdout)
    result = evaluate_cedar_v2(
        [{"finding_id": "image-1", "severity": "high", "category": "container_scanning"}],
        baseline=TrustedBaseline("none", None, frozenset()),
        bundle_path=str(bundle), binary_path=binary, binary_sha256=pin,
    )
    assert result["status"] == "failed"
    assert result["determining_policy_ids"] == ["project/container_images_new"]
