"""Optional cross-project PLAN-09/Cedar parity corpus using the real Rust binary."""

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from ez_appsec.cedar_adapter import evaluate_cedar, parity_result
from ez_appsec.policy import PolicyEngine, PolicyRule


@pytest.mark.integration
def test_supported_plan09_rule_corpus_matches_cedar(tmp_path):
    binary = os.getenv("SOURCEBASTION_POLICY_ENGINE_BINARY")
    if not binary:
        pytest.skip("set SOURCEBASTION_POLICY_ENGINE_BINARY for live parity proof")
    pin = hashlib.sha256(Path(binary).read_bytes()).hexdigest()

    cases = [
        ("empty", [], []),
        ("zero_boundary", [dict(severity="critical", max_count=0)], []),
        ("one_over_zero", [dict(severity="critical", max_count=0)], [dict(severity="critical", category="secrets")]),
        ("exact_threshold", [dict(category="secrets", max_count=2)], [dict(category="secrets") for _ in range(2)]),
        ("over_threshold", [dict(category="secrets", max_count=2)], [dict(category="secrets") for _ in range(3)]),
        ("case_normalization", [dict(severity="high")], [dict(severity="High", category="sast")]),
        ("type_fallback", [dict(category="secrets")], [dict(severity="high", type="secrets")]),
        ("scanner_fallback", [dict(category="sast")], [dict(severity="medium", scanner="sast")]),
        ("intersection", [dict(severity="critical", category="secrets")], [
            dict(severity="critical", category="sast"), dict(severity="high", category="secrets"),
            dict(severity="critical", category="secrets")]),
        ("warning_only", [dict(severity="high", action="warn")], [dict(severity="high", category="sast")]),
        ("ignore_noop", [dict(severity="critical", action="ignore")], [dict(severity="critical", category="secrets")]),
        ("unknown", [dict(severity="high", category="secrets")], [dict(severity="mystery", category="unknown")]),
        ("duplicate_rules", [dict(severity="critical"), dict(severity="critical")],
         [dict(severity="critical", category="secrets")]),
        ("suppressed_input", [dict(severity="critical")], []),
    ]

    for name, raw_rules, findings in cases:
        rules = [PolicyRule(**rule) for rule in raw_rules]
        converted = subprocess.run([binary, "convert-plan09"],
                                   input=json.dumps(raw_rules).encode(), capture_output=True, check=False, timeout=8)
        assert converted.returncode == 0, name
        bundle = json.loads(converted.stdout)["bundle"]
        bundle_file = tmp_path / f"{name}.json"
        bundle_file.write_text(json.dumps({"bundles": [bundle]}), encoding="utf-8")
        cedar = evaluate_cedar(findings, bundle_path=str(bundle_file), binary_path=binary, binary_sha256=pin)
        legacy = PolicyEngine(rules).evaluate(findings)
        expected_status = "failed" if legacy["failed"] else "passed"
        assert cedar["status"] == expected_status, name
        parity = parity_result(findings, rules, cedar)
        assert parity["mismatch"] is False, name
        assert cedar["warning_policy_ids"] == parity["legacy_warning_ids"], name
        assert cedar["determining_policy_ids"] == parity["legacy_fail_ids"], name

    unsupported = subprocess.run([binary, "convert-plan09"], input=b'[{"max_count":-1}]',
                                 capture_output=True, check=False, timeout=8)
    assert unsupported.returncode == 2
    assert json.loads(unsupported.stdout)["error_code"] == "UNSUPPORTED_PLAN09_RULE"
