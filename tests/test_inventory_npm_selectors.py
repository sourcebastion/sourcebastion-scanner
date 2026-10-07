"""Actual pinned npm grammar; no npm installation or project loading."""

import json
import subprocess
import time

import pytest

from sourcebastion.inventory import npm_selectors
from sourcebastion.inventory.inputs import InputRefusal

CASES = [
    ("1.2.3", "^1.0.0", "match"),
    ("2.0.0", "^1.0.0", "nonmatch"),
    ("0.2.9", "^0.2.3", "match"),
    ("0.3.0", "^0.2.3", "nonmatch"),
    ("0.0.4", "^0.0.3", "nonmatch"),
    ("0.0.3", "^0.0.3", "match"),
    ("1.2.3-beta.4", "^1.2.3-beta.2", "match"),
    ("1.2.4-beta.2", "^1.2.3-beta.2", "nonmatch"),
    ("1.2.3-beta.2", "*", "nonmatch"),
    ("1.2.3+build.9", "=1.2.3", "match"),
    ("1.2.3+build.9", "1.2.3+other", "match"),
    ("1.2.99", "~1.2.3", "match"),
    ("1.3.0", "~1.2.3", "nonmatch"),
    ("2.3.9", "1.2 - 2.3", "match"),
    ("2.4.0", "1.2 - 2.3", "nonmatch"),
    ("1.7.8", "1.x", "match"),
    ("2.7.8", "1.x", "nonmatch"),
    ("2.5.1", ">=1.0.0 <2 || >=2.5.0 <3", "match"),
    ("2.3.4", "", "match"),
    ("2.3.4", ">1", "match"),
    ("1.9.9", ">1", "nonmatch"),
    ("1.2.3", "v1.2.3", "match"),
    ("v1.2.3", "1.2.3", "invalid-version"),
    ("1.2", "*", "invalid-version"),
    ("01.2.3", "*", "invalid-version"),
    ("1.2.3", "npm:other@1.2.3", "invalid-range"),
    ("1.2.3", "https://secret-token@packages.invalid/pkg", "invalid-range"),
]


def test_upstream_npm_semantics_in_one_actual_batch():
    calls = []
    result = npm_selectors.evaluate(
        [(version, selector) for version, selector, _expected in CASES],
        deadline=time.monotonic() + 20,
        check=lambda: calls.append(1),
    )
    assert result == tuple(expected for _version, _selector, expected in CASES)
    assert len(calls) == 2 * len(CASES) + 2


def test_trusted_parser_does_not_load_project_modules_scripts_or_node_options(tmp_path, monkeypatch):
    malicious = tmp_path / "customer.cjs"
    sentinel = tmp_path / "executed"
    malicious.write_text("require('fs').writeFileSync(" + json.dumps(str(sentinel)) + ", 'bad')")
    monkeypatch.setenv("NODE_OPTIONS", "--require " + str(malicious))
    monkeypatch.setenv("NODE_V8_COVERAGE", str(tmp_path / "coverage"))
    fake = tmp_path / "node_modules/semver"
    fake.mkdir(parents=True)
    (fake / "index.js").write_text(malicious.read_text())
    (tmp_path / "package.json").write_text('{"scripts":{"preinstall":"node customer.cjs"}}')
    monkeypatch.chdir(tmp_path)
    before = {str(path.relative_to(tmp_path)): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    assert npm_selectors.evaluate((("1.2.3", "^1"),), deadline=time.monotonic() + 20, check=lambda: None) == ("match",)
    assert not sentinel.exists() and not (tmp_path / "coverage").exists()
    assert before == {
        str(path.relative_to(tmp_path)): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    }


@pytest.mark.parametrize(
    "queries",
    [
        (("1.2.3", "x" * 16385),),
        (("1" * 129, "*"),),
        (("1.2.3", "1 || " * 129),),
        (("1.2.3", "bad\x7fsecret-token"),),
        (("1.2.3", None),),
        (("1.2.3",),),
    ],
)
def test_query_budgets_refuse_before_spawning(tmp_path, monkeypatch, queries):
    def prohibited(*args, **kwargs):
        raise AssertionError("budget refusal spawned a parser")

    monkeypatch.setattr(subprocess, "run", prohibited)
    with pytest.raises(InputRefusal):
        npm_selectors.evaluate(queries, deadline=time.monotonic() + 20, check=lambda: None)


def test_deadline_and_shared_ledger_are_preserved(monkeypatch):
    with pytest.raises(InputRefusal, match="deadline"):
        npm_selectors.evaluate((("1.2.3", "*"),), deadline=time.monotonic() - 1, check=lambda: None)
    calls = 0

    def check():
        nonlocal calls
        calls += 1
        if calls > 3:
            raise InputRefusal("composition-check-budget-exceeded")

    with pytest.raises(InputRefusal, match="composition-check-budget-exceeded"):
        npm_selectors.evaluate((("1.2.3", "*"),) * 2, deadline=time.monotonic() + 20, check=check)
    assert calls == 4


def test_failing_or_missing_runtime_returns_only_fixed_diagnostic(monkeypatch):
    for failure in [OSError("customer-token"), subprocess.TimeoutExpired("private-customer-command", 1)]:

        def refused(*args, **kwargs):
            raise failure

        monkeypatch.setattr(subprocess, "run", refused)
        with pytest.raises(InputRefusal) as caught:
            npm_selectors.evaluate((("1.2.3", "*"),), deadline=time.monotonic() + 20, check=lambda: None)
        assert "customer" not in str(caught.value)


def test_vendor_hashes_match_pinned_immutable_upstream():
    assert npm_selectors.verify_vendor() == "85a15ddf20cf437c7b886df975c3e897daa4cfcd494df85b13091053132b54f3"
