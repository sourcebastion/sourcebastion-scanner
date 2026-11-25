import json
from pathlib import Path
import random
import shutil
import string
import subprocess
import time

import pytest

from sourcebastion.external_scanners import GitleaksScanner
from sourcebastion.secret_likelihood import gitleaks_benign_codes, gitleaks_likelihood_code


def test_context_is_advisory_and_rule_family_takes_precedence():
    assert gitleaks_likelihood_code("github-pat", "docs/example.py", 5.0) == "v1:credential-format"
    assert gitleaks_likelihood_code("generic-api-key", "tests/example.py", 5.0) == "v1:generic-test"
    assert gitleaks_likelihood_code("generic-api-key", "app.py", 5.0) == "v1:generic-entropy"
    assert gitleaks_likelihood_code("generic-api-key", "app.py", float("nan")) == "v1:generic"
    assert gitleaks_likelihood_code("unrecognized-rule", "docs/example.py", 5.0) is None


def test_exact_check_rejects_symlinks_multiline_and_wrong_coordinates(tmp_path):
    value = "YOUR_SERVICE_API_KEY_HERE"
    line = f'service_api_key = "{value}"'
    (tmp_path / "app.py").write_text(line)
    (tmp_path / "alias.py").symlink_to(tmp_path / "app.py")
    stored = {"RuleID": "generic-api-key", "Secret": "REDACTED",
              "Match": 'service_api_key = "REDACTED"', "StartLine": 1,
              "EndLine": 1, "StartColumn": 1, "EndColumn": len(line)}
    scan_started = time.time_ns()
    assert gitleaks_benign_codes(tmp_path, [("app.py", stored), ("alias.py", stored),
        ("app.py", {**stored, "EndLine": 2}),
        ("app.py", {**stored, "StartColumn": 2})], scan_started_ns=scan_started) == {0: "v1:placeholder"}
    assert gitleaks_benign_codes(tmp_path, [
        ("app.py", stored), ("app.py", {**stored, "RuleID": "github-pat"}),
    ], scan_started_ns=scan_started) == {}
    assert gitleaks_benign_codes(tmp_path, [("app.py", stored)],
        scan_started_ns=(tmp_path / "app.py").stat().st_ctime_ns - 1) == {}


def test_explicit_publishable_assignment_is_checked_within_shared_budget(tmp_path):
    rng = random.Random(670928)
    value = "".join(rng.choices(string.ascii_letters + string.digits, k=32))
    line = f'STRIPE_PUBLISHABLE_KEY = "pk_test_{value}"'
    (tmp_path / "z.py").write_text(line)
    evidence = {"RuleID": "generic-api-key", "Secret": "REDACTED",
                "StartLine": 1, "EndLine": 1, "StartColumn": 1, "EndColumn": len(line)}
    broad = {**evidence, "Match": 'service_api_key = "REDACTED"'}
    known = {**evidence, "Match": 'STRIPE_PUBLISHABLE_KEY = "REDACTED"'}
    findings = [(f"a-{n}.py", broad) for n in range(128)] + [("z.py", known)]
    scan_started = time.time_ns()
    assert gitleaks_benign_codes(tmp_path, findings, scan_started_ns=scan_started) == {128: "v1:public-key"}
    assert gitleaks_benign_codes(tmp_path, list(reversed(findings)), scan_started_ns=scan_started) == {
        0: "v1:public-key",
    }


@pytest.mark.skipif(shutil.which("gitleaks") is None or shutil.which("git") is None,
                    reason="requires the pinned Gitleaks binary and Git")
def test_stock_history_does_not_apply_worktree_evidence_to_a_commit(tmp_path):
    rng = random.Random(671128)
    alphabet = string.ascii_letters + string.digits
    publishable = "pk_test_" + "".join(rng.choices(alphabet, k=32))
    server = "ghp_" + "".join(rng.choices(alphabet, k=36))
    (tmp_path / "settings.yml").write_text(f'stripe_publishable_key: "{publishable}"\n')
    (tmp_path / "server.py").write_text(f'github_token = "{server}"\n')
    for args in (("init", "-q"), ("add", "."), ("-c", "user.name=Fixture",
                 "-c", "user.email=fixture@example.invalid", "commit", "-qm", "synthetic")):
        subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)

    scanner = GitleaksScanner()
    current = {row["rule_id"]: row for row in scanner.scan_current_tree(str(tmp_path))}
    history, artifact = scanner.scan_with_raw_output(str(tmp_path))
    Path(artifact).unlink()
    history = {row["rule_id"]: row for row in history}
    assert history.keys() == current.keys() == {"generic-api-key", "github-pat"}
    assert current["generic-api-key"]["secret_likelihood"] == "v1:public-key"
    assert history["generic-api-key"]["secret_likelihood"] == "v1:generic-entropy"
    assert current["github-pat"]["secret_likelihood"] == history["github-pat"]["secret_likelihood"] == (
        "v1:credential-format"
    )
    assert all(row["severity"] == "critical" for row in (*current.values(), *history.values()))


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="requires the pinned Gitleaks binary")
def test_redacted_stock_scans_keep_findings_and_classify_held_out_examples(tmp_path):
    # These deterministic strings are created offline and have no provider rights.
    rng = random.Random(670817)
    fixtures = {}
    alphabet = string.ascii_letters + string.digits
    root = tmp_path / "source"
    root.mkdir()
    for index in range(48):
        token = "".join(rng.choices(alphabet, k=32))
        if index < 24:
            assignment, candidate = "STRIPE_PUBLISHABLE_KEY", "pk_test_" + token
        elif index < 36:
            assignment, candidate = "STRIPE_PRIVATE_KEY", "sk_test_" + token
        else:
            assignment, candidate = "SERVICE_API_KEY", "pk_test_" + token
        name = f"case{index}.py"
        fixtures[name] = candidate
        (root / name).write_text(f'{assignment} = "{candidate}"\n')
    scanner = GitleaksScanner()
    first = scanner.scan_current_tree(str(root))
    second = scanner.scan_current_tree(str(root))
    observed = {row["file"]: row["secret_likelihood"] for row in first}
    assert len(first) == len(fixtures) == 48
    assert observed == {row["file"]: row["secret_likelihood"] for row in second}
    assert sum(code == "v1:public-key" for code in observed.values()) == 24
    assert all(observed[f"case{index}.py"] == "v1:public-key" for index in range(24))
    assert all(observed[f"case{index}.py"] == "v1:credential-format" for index in range(24, 36))
    assert all(observed[f"case{index}.py"].startswith("v1:generic") for index in range(36, 48))
    assert all(row["severity"] == "critical" for row in first)
    encoded = json.dumps(first)
    assert all(value not in encoded for value in fixtures.values())
