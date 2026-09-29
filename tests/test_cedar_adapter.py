"""M042 scanner-consumer contract tests; Cedar itself lives in a separate repo."""

import hashlib
import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner
from ez_appsec.cli import main
from ez_appsec.cedar_adapter import evaluate_cedar, parity_result, snapshot_from_findings
from ez_appsec.config import Config, IgnoreRule
from ez_appsec.external_scanners import ScannerExecutionError
from ez_appsec.policy import PolicyRule
from ez_appsec.scanner import SecurityScanner


def test_summary_is_complete_and_contains_no_raw_finding_data():
    findings = [
        {"severity": "Critical", "category": "secrets", "secret": "never-send-me", "file": "src/secret.py"},
        {"severity": "mystery", "type": "sast", "message": "private details"},
    ]
    snapshot = snapshot_from_findings(findings)
    assert snapshot["finding_count"] == 2
    assert snapshot["severity"]["critical"] == 1
    assert snapshot["severity"]["unknown"] == 1
    assert snapshot["by_category"]["secrets"]["critical"] == 1
    assert snapshot["by_category"]["sast"]["unknown"] == 1
    assert "never-send-me" not in json.dumps(snapshot)
    assert "src/secret.py" not in json.dumps(snapshot)
    without_digest = {key: value for key, value in snapshot.items() if key != "digest"}
    canonical = json.dumps(without_digest, sort_keys=True, separators=(",", ":"))
    assert snapshot["digest"] == "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def test_missing_binary_or_bundle_is_error_not_pass(tmp_path):
    assert evaluate_cedar([], bundle_path=None, binary_path=None, binary_sha256=None)["status"] == "error"
    bundle = tmp_path / "bundle.json"
    bundle.write_text('{"bundles":[]}', encoding="utf-8")
    result = evaluate_cedar([], bundle_path=str(bundle), binary_path=str(tmp_path / "missing"),
                            binary_sha256="0" * 64)
    assert result["status"] == "error"
    assert result["diagnostic_codes"] == ["BINARY_PIN_MISMATCH"]


def test_parity_tracks_rule_indices_including_ignored_rule():
    findings = [{"severity": "critical", "category": "secrets"}]
    rules = [PolicyRule(action="ignore"), PolicyRule(severity="critical", action="fail"),
             PolicyRule(category="secrets", action="warn")]
    cedar = {"status": "failed", "determining_policy_ids": ["plan09/plan09_rule_0002"],
             "warning_policy_ids": ["plan09/plan09_rule_0003"]}
    parity = parity_result(findings, rules, cedar)
    assert parity["mismatch"] is False
    assert parity["legacy_fail_ids"] == ["plan09/plan09_rule_0002"]
    assert parity_result(findings, rules, {"status": "error"})["mismatch"] is True


def test_shadow_records_error_without_changing_legacy_failure(monkeypatch, tmp_path):
    config = Config(policy_mode="shadow", policy_rules=[PolicyRule(severity="critical")],
                    output_file=str(tmp_path / "vulnerabilities.json"))
    scanner = SecurityScanner(config, use_external_scanners=False)

    class FakeExternal:
        def scan_all(self, _path):
            return [{"severity": "critical", "category": "secrets", "title": "test",
                     "description": "test", "rule_id": "test", "file": "test.py", "line": 1}]

    scanner.use_external = True
    scanner.external = FakeExternal()
    monkeypatch.setattr("ez_appsec.scanner.evaluate_cedar", lambda *_args, **_kwargs:
                        {"status": "error", "diagnostic_codes": ["BINARY_PIN_MISMATCH"],
                         "determining_policy_ids": [], "warning_policy_ids": []})
    result = scanner.scan(str(tmp_path))
    assert result["policy_failed"] is True
    assert result["policy_cedar"]["status"] == "error"
    assert result["policy_parity"]["mismatch"] is True
    artifact = json.loads((tmp_path / "vulnerabilities.json.policy-result.json").read_text(encoding="utf-8"))
    assert artifact["schema_version"] == 1
    assert artifact["mode"] == "shadow"
    findings_artifact = json.loads((tmp_path / "vulnerabilities.json").read_text(encoding="utf-8"))
    assert "policy_cedar" not in findings_artifact


def test_default_mode_remains_legacy():
    assert Config().policy_mode == "legacy"


def test_adapter_sees_post_suppression_snapshot_before_display_filter(monkeypatch, tmp_path):
    config = Config(policy_mode="shadow", severity="high",
                    ignore_rules=[IgnoreRule(rule_id="suppressed", permanent=True)])
    scanner = SecurityScanner(config, use_external_scanners=False)

    class FakeExternal:
        def scan_all(self, _path):
            return [
                {"severity": "critical", "category": "secrets", "rule_id": "critical", "title": "c", "description": "c"},
                {"severity": "low", "category": "sast", "rule_id": "low", "title": "l", "description": "l"},
                {"severity": "high", "category": "sast", "rule_id": "suppressed", "title": "s", "description": "s"},
            ]

    scanner.use_external = True
    scanner.external = FakeExternal()
    observed = []

    def fake_evaluate(findings, **_kwargs):
        observed.extend(findings)
        return {"status": "passed", "determining_policy_ids": [], "warning_policy_ids": [],
                "diagnostic_codes": []}

    monkeypatch.setattr("ez_appsec.scanner.evaluate_cedar", fake_evaluate)
    result = scanner.scan(str(tmp_path))
    assert result["suppressed"] == 1
    assert len(observed) == 2
    assert {finding["rule_id"] for finding in observed} == {"critical", "low"}
    assert {finding["rule_id"] for finding in result["issues"]} == {"critical"}


def test_policy_and_artifact_include_image_findings(monkeypatch, tmp_path):
    config = Config(
        policy_mode="shadow",
        policy_rules=[PolicyRule(severity="high", max_count=0)],
        output_file=str(tmp_path / "vulnerabilities.json"),
    )
    scanner = SecurityScanner(config, use_external_scanners=False)

    class FakeExternal:
        def scan_all(self, _path):
            return [{"severity": "low", "category": "sast", "rule_id": "code",
                     "title": "code", "description": "code", "file": "code.py", "line": 1}]

    scanner.use_external = True
    scanner.external = FakeExternal()
    image_calls = []

    def fake_image_scan(_self, image, registry_auth=None):
        image_calls.append((image, registry_auth))
        return [{"severity": "high", "category": "container_scanning", "rule_id": "image",
                 "title": "image", "description": "image", "file": "image:app", "line": 1}]

    monkeypatch.setattr("ez_appsec.external_scanners.GrypeImageScanner.scan", fake_image_scan)
    observed = []

    def fake_evaluate(findings, **_kwargs):
        observed.extend(findings)
        return {"status": "failed", "determining_policy_ids": ["repository/image"],
                "warning_policy_ids": [], "diagnostic_codes": []}

    monkeypatch.setattr("ez_appsec.scanner.evaluate_cedar", fake_evaluate)
    result = scanner.scan(str(tmp_path), image="app:1", registry_auth="user:token")

    assert image_calls == [("app:1", "user:token")]
    assert {finding["rule_id"] for finding in observed} == {"code", "image"}
    assert result["policy_failed"] is True
    assert result["policy_cedar"]["status"] == "failed"
    assert result["scanner_results"]["image"] == 1
    assert result["scan_record"]["finding_count"] == 2
    assert result["total"] == 2
    artifact = json.loads((tmp_path / "vulnerabilities.json").read_text(encoding="utf-8"))
    assert {finding["category"] for finding in artifact["vulnerabilities"]} == {
        "sast", "container",
    }


def test_cli_cedar_error_exits_two_but_shadow_error_keeps_legacy_exit(monkeypatch, tmp_path):
    monkeypatch.setattr("ez_appsec.external_scanners.ExternalScannerManager.scan_all", lambda *_args: [])
    config_path = tmp_path / ".ez-appsec.yaml"
    runner = CliRunner()

    config_path.write_text("policy_mode: cedar\n", encoding="utf-8")
    enforcing = runner.invoke(main, ["scan", str(tmp_path), "--config", str(config_path)])
    assert enforcing.exit_code == 2
    assert "could not be evaluated" in enforcing.output

    config_path.write_text("policy_mode: shadow\n", encoding="utf-8")
    shadow = runner.invoke(main, ["scan", str(tmp_path), "--config", str(config_path)])
    assert shadow.exit_code == 0
    assert "parity mismatch or evaluation error" in shadow.output


def test_cli_cedar_gate_can_fail_on_image_finding(monkeypatch, tmp_path):
    monkeypatch.setattr("ez_appsec.external_scanners.ExternalScannerManager.scan_all", lambda *_args: [])
    monkeypatch.setattr(
        "ez_appsec.external_scanners.GrypeImageScanner.scan",
        lambda *_args, **_kwargs: [
            {"severity": "high", "category": "container_scanning", "rule_id": "image",
             "title": "image", "description": "image", "file": "image:app", "line": 1}
        ],
    )
    observed = []

    def fake_evaluate(findings, **_kwargs):
        observed.extend(findings)
        return {"status": "failed", "determining_policy_ids": ["repository/image"],
                "warning_policy_ids": [], "diagnostic_codes": []}

    monkeypatch.setattr("ez_appsec.scanner.evaluate_cedar", fake_evaluate)
    config_path = tmp_path / ".ez-appsec.yaml"
    config_path.write_text("policy_mode: cedar\n", encoding="utf-8")

    result = CliRunner().invoke(main, [
        "scan", str(tmp_path), "--config", str(config_path), "--image", "app:1",
    ])

    assert result.exit_code == 1
    assert {finding["rule_id"] for finding in observed} == {"image"}
    assert "Container image scan: 1 finding" in result.output
    assert "Cedar policy check failed" in result.output


def test_image_component_failure_never_writes_an_authoritative_pass(tmp_path, monkeypatch):
    config = Config(output_file=str(tmp_path / "vulnerabilities.json"))
    scanner = SecurityScanner(config, use_external_scanners=False)
    monkeypatch.setattr(
        "ez_appsec.external_scanners.GrypeImageScanner.scan",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ScannerExecutionError("grype-image", "output_missing")
        ),
    )

    with pytest.raises(ScannerExecutionError):
        scanner.scan(str(tmp_path), image="app:1")

    assert not (tmp_path / "vulnerabilities.json").exists()


@pytest.mark.integration
def test_live_engine_over_real_scanner_artifacts(tmp_path):
    """Run with the standalone release binary and example bundle when available."""
    binary = os.getenv("SOURCEBASTION_POLICY_ENGINE_BINARY")
    bundle = os.getenv("SOURCEBASTION_POLICY_ENGINE_BUNDLE")
    if not binary or not bundle:
        pytest.skip("set SOURCEBASTION_POLICY_ENGINE_BINARY and _BUNDLE for live proof")
    binary_path = Path(binary)
    pin = hashlib.sha256(binary_path.read_bytes()).hexdigest()
    cases = [
        ("clean", [], "passed", []),
        ("blocked", [{"severity": "critical", "category": "secrets"}], "failed", []),
        ("warning", [{"severity": "high", "category": "sast"}], "passed", ["repository/warn_high_sast"]),
    ]
    for name, findings, expected_status, expected_warnings in cases:
        output_path = tmp_path / name / "vulnerabilities.json"
        output_path.parent.mkdir(parents=True)
        config = Config(policy_mode="cedar", cedar_policy_bundle=bundle,
                        cedar_policy_binary=binary, cedar_binary_sha256=pin,
                        output_file=str(output_path))
        scanner = SecurityScanner(config, use_external_scanners=False)

        class FakeExternal:
            def scan_all(self, _path):
                return [dict(finding, rule_id="fixture", title="fixture", description="fixture")
                        for finding in findings]

        scanner.use_external = True
        scanner.external = FakeExternal()
        result = scanner.scan(str(output_path.parent))
        assert result["policy_cedar"]["status"] == expected_status
        assert result["policy_cedar"]["warning_policy_ids"] == expected_warnings
        artifact = json.loads(output_path.with_name(output_path.name + ".policy-result.json").read_text())
        assert artifact["result"]["status"] == expected_status
        assert artifact["schema_version"] == 1
