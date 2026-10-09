"""Concurrent rule-fixture verification must not change what it reports.

The verifier costs three semgrep process starts per rule, so it runs rules
concurrently. Concurrency is only acceptable here if the result is identical to
the serialized run -- same verdict, same lines, same order -- otherwise a
reviewer cannot read a failure list and a flake becomes indistinguishable from
a real rule regression.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts/verify-rule-fixtures.py"

STUB = """#!/usr/bin/env bash
# Mimics semgrep's startup cost, and reports a finding only for a target whose
# text carries a `ruleid:` reference.
target="$3"
sleep 0.05
if [ -d "$target" ]; then echo '{"results": [], "errors": []}'; exit 0; fi
if grep -q 'ruleid:' "$target" 2>/dev/null; then
  echo '{"results": [{"check_id": "x"}], "errors": []}'
else
  echo '{"results": [], "errors": []}'
fi
"""

RULE = """rules:
  - id: {rule_id}
    pattern: $X == $X
    message: test
    languages: [python]
    severity: WARNING
"""


@pytest.fixture
def corpus(tmp_path):
    """A rules tree the verifier can walk, plus a stub semgrep on PATH."""
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    stub = stub_dir / "semgrep"
    stub.write_text(STUB)
    stub.chmod(0o755)

    rules = tmp_path / "rules" / "python"
    tests = rules / "tests"
    tests.mkdir(parents=True)
    # Enough rules that concurrency has something to interleave, and a mix of
    # passing and failing so the failure list's order is exercised too.
    for index in range(8):
        rule_id = f"rule-{index}"
        (rules / f"{rule_id}.yaml").write_text(RULE.format(rule_id=rule_id))
        (tests / f"{rule_id}_tp.py").write_text(f"# ruleid: {rule_id}\nx = 1\n")
        if index % 3:
            (tests / f"{rule_id}_tn.py").write_text(f"# ok: {rule_id}\ny = 2\n")
    return tmp_path, stub_dir


def run(cwd, stub_dir, jobs):
    return subprocess.run(
        [sys.executable, str(VERIFIER), "--jobs", str(jobs)],
        cwd=cwd,
        env={**os.environ, "PATH": f"{stub_dir}:{os.environ['PATH']}"},
        capture_output=True,
        text=True,
    )


def test_concurrent_and_serialized_runs_agree_exactly(corpus):
    cwd, stub_dir = corpus

    serial = run(cwd, stub_dir, 1)
    parallel = run(cwd, stub_dir, 8)

    assert parallel.returncode == serial.returncode
    assert parallel.stdout == serial.stdout, "verdict lines must match in order"
    assert parallel.stderr == serial.stderr, "failure list must match in order"


def test_the_corpus_actually_exercises_both_outcomes(corpus):
    """Guards the test above: agreement on an all-passing corpus would prove
    little, since failure ordering is what concurrency could disturb."""
    cwd, stub_dir = corpus

    result = run(cwd, stub_dir, 4)

    assert result.returncode == 1
    assert "OK python/" in result.stdout
    assert "no true-negative fixture" in result.stderr


def test_repeated_concurrent_runs_are_stable(corpus):
    """Order must come from the rule list, not from completion timing."""
    cwd, stub_dir = corpus

    outputs = {run(cwd, stub_dir, 8).stdout for _ in range(3)}

    assert len(outputs) == 1


def test_concurrency_is_bounded_by_the_rule_count(corpus):
    """A larger --jobs than there are rules must not fail or change output."""
    cwd, stub_dir = corpus

    modest = run(cwd, stub_dir, 2)
    excessive = run(cwd, stub_dir, 512)

    assert excessive.returncode == modest.returncode
    assert excessive.stdout == modest.stdout
