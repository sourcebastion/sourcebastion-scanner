"""Exercise the installed scanner wheel against a pinned standalone engine binary."""

import argparse
import hashlib
import json
from pathlib import Path

import ez_appsec
from ez_appsec.config import Config
from ez_appsec.policy import PolicyRule
from ez_appsec.scanner import SecurityScanner


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", required=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--artifacts", required=True)
    args = parser.parse_args()
    installed_from = Path(ez_appsec.__file__).resolve()
    assert "site-packages" in installed_from.parts, installed_from
    binary = Path(args.engine).resolve()
    bundle = Path(args.bundle).resolve()
    pin = hashlib.sha256(binary.read_bytes()).hexdigest()

    def run_case(name, findings, *, mode="cedar", bundle_file=bundle, rules=None):
        output_dir = Path(args.artifacts) / name
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / "vulnerabilities.json"
        cedar_config = ({"cedar_policy_bundle": str(bundle_file),
                         "cedar_policy_binary": str(binary), "cedar_binary_sha256": pin}
                        if mode != "legacy" else {})
        config = Config(policy_mode=mode, policy_rules=rules or [],
                        output_file=str(output_path), **cedar_config)
        scanner = SecurityScanner(config, use_external_scanners=False)

        class FakeExternal:
            def scan_all(self, _path):
                return [dict(finding, rule_id="fixture", title="fixture", description="fixture")
                        for finding in findings]

        scanner.use_external = True
        scanner.external = FakeExternal()
        result = scanner.scan(str(output_dir))
        policy_artifact = output_path.with_name(output_path.name + ".policy-result.json")
        persisted = json.loads(policy_artifact.read_text(encoding="utf-8")) if policy_artifact.exists() else None
        return result, persisted

    cases = (
        ("clean", [], "passed", []),
        ("blocked", [{"severity": "critical", "category": "secrets"}], "failed", []),
        ("warning", [{"severity": "high", "category": "sast"}], "passed", ["repository/warn_high_sast"]),
    )
    for name, findings, expected_status, expected_warnings in cases:
        result, persisted = run_case(name, findings)
        assert result["policy_cedar"]["status"] == expected_status, name
        assert result["policy_cedar"]["warning_policy_ids"] == expected_warnings, name
        assert persisted["schema_version"] == 1, name
        assert persisted["result"]["status"] == expected_status, name
        print(f"{name}: {expected_status}; installed={installed_from}")

    malformed_bundle = Path(args.artifacts) / "malformed-bundle.json"
    malformed_bundle.write_text(json.dumps({"bundles": [{"id": "repository", "policies": [
        {"id": "broken", "source": "not Cedar"}]}]}), encoding="utf-8")
    malformed, persisted = run_case("malformed", [], bundle_file=malformed_bundle)
    assert malformed["policy_cedar"]["status"] == "error"
    assert malformed["policy_cedar"]["diagnostic_codes"] == ["INVALID_POLICY"]
    assert persisted["result"]["status"] == "error"
    print(f"malformed: error; installed={installed_from}")

    empty_bundle = Path(args.artifacts) / "empty-bundle.json"
    empty_bundle.write_text('{"bundles":[{"id":"repository","policies":[]}]}', encoding="utf-8")
    critical = [{"severity": "critical", "category": "secrets"}]
    legacy_rules = [PolicyRule(severity="critical")]
    shadow, persisted = run_case("shadow-mismatch", critical, mode="shadow",
                                 bundle_file=empty_bundle, rules=legacy_rules)
    assert shadow["policy_failed"] is True
    assert shadow["policy_cedar"]["status"] == "passed"
    assert shadow["policy_parity"]["mismatch"] is True
    assert persisted["mode"] == "shadow"
    assert persisted["parity"]["mismatch"] is True
    print(f"shadow-mismatch: legacy failed, Cedar passed; installed={installed_from}")

    rollback, persisted = run_case("rollback", critical, mode="legacy", rules=legacy_rules)
    assert rollback["policy_failed"] is True
    assert "policy_cedar" not in rollback
    assert persisted is None
    print(f"rollback: legacy failed without Cedar; installed={installed_from}")


if __name__ == "__main__":
    main()
