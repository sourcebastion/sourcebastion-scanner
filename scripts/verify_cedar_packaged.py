"""Exercise the installed scanner wheel against a pinned standalone engine binary."""

import argparse
import hashlib
import json
from pathlib import Path

import ez_appsec
from ez_appsec.config import Config
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
    cases = (
        ("clean", [], "passed", []),
        ("blocked", [{"severity": "critical", "category": "secrets"}], "failed", []),
        ("warning", [{"severity": "high", "category": "sast"}], "passed", ["repository/warn_high_sast"]),
    )
    for name, findings, expected_status, expected_warnings in cases:
        output_dir = Path(args.artifacts) / name
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / "vulnerabilities.json"
        config = Config(policy_mode="cedar", cedar_policy_bundle=str(bundle),
                        cedar_policy_binary=str(binary), cedar_binary_sha256=pin,
                        output_file=str(output_path))
        scanner = SecurityScanner(config, use_external_scanners=False)

        class FakeExternal:
            def scan_all(self, _path):
                return [dict(finding, rule_id="fixture", title="fixture", description="fixture")
                        for finding in findings]

        scanner.use_external = True
        scanner.external = FakeExternal()
        result = scanner.scan(str(output_dir))
        assert result["policy_cedar"]["status"] == expected_status, name
        assert result["policy_cedar"]["warning_policy_ids"] == expected_warnings, name
        policy_artifact = output_path.with_name(output_path.name + ".policy-result.json")
        persisted = json.loads(policy_artifact.read_text(encoding="utf-8"))
        assert persisted["schema_version"] == 1, name
        assert persisted["result"]["status"] == expected_status, name
        print(f"{name}: {expected_status}; installed={installed_from}")


if __name__ == "__main__":
    main()
