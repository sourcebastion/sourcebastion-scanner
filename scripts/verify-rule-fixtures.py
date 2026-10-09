#!/usr/bin/env python3
"""Verify custom semgrep rule packs against their TP/TN fixtures.

This script is intentionally dependency-light enough to run inside SourceBastion
Docker images after they are built. It verifies every rule file under rules/*:
  - rule YAML is parseable by semgrep
  - its true-positive fixture produces at least one finding
  - its true-negative fixture produces zero findings

Fixture mapping is discovered from inline comments:
  # ruleid: <rule-id>
  # ok: <rule-id>
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

RULES_ROOT = Path("rules")
LANGUAGES = ["python", "ruby", "java", "javascript", "php"]
RULEREF_RE = re.compile(r"ruleid:\s*([\w.-]+)|ok:\s*([\w.-]+)")


def run_semgrep(rule_yaml: Path, target: Path) -> tuple[int, list[str]]:
    proc = subprocess.run(
        ["semgrep", "--config", str(rule_yaml), str(target), "--json", "--quiet"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return -1, [f"semgrep produced non-JSON output (rc={proc.returncode}): {proc.stderr[:200]}"]
    findings = len(data.get("results", []))
    errors = [
        str(e.get("message", e))[:200]
        for e in data.get("errors", [])
        if e.get("code") != "TargetParseError"
    ]
    return findings, errors


def load_rule_id(rule_yaml: Path) -> str:
    data = yaml.safe_load(rule_yaml.read_text())
    rules = data.get("rules", [])
    if not rules or not rules[0].get("id"):
        raise ValueError(f"{rule_yaml}: missing rules[0].id")
    return str(rules[0]["id"])


def fixtures_for_rule(rule_yaml: Path, language: str) -> tuple[Path | None, Path | None]:
    rule_id = load_rule_id(rule_yaml)
    tests_dir = RULES_ROOT / language / "tests"
    tp = tn = None
    for fixture in tests_dir.iterdir():
        if not fixture.is_file():
            continue
        refs = {m.group(1) or m.group(2) for m in RULEREF_RE.finditer(fixture.read_text())}
        if rule_id not in refs:
            continue
        if "_tp" in fixture.name.lower():
            tp = fixture
        elif "_tn" in fixture.name.lower():
            tn = fixture
    return tp, tn


def all_rules() -> list[tuple[str, Path]]:
    cases: list[tuple[str, Path]] = []
    for language in LANGUAGES:
        lang_dir = RULES_ROOT / language
        if not lang_dir.is_dir():
            continue
        for rule_yaml in sorted(lang_dir.glob("*.yaml")):
            cases.append((language, rule_yaml))
    return cases


def empty_target_dir() -> Path:
    """Created once by the caller; workers must not race on mkdir."""
    target = Path(tempfile.gettempdir()) / "sourcebastion_empty_target"
    target.mkdir(exist_ok=True)
    return target


def validate_rule(rule_yaml: Path, empty_target: Path | None = None) -> list[str]:
    _, errors = run_semgrep(rule_yaml, empty_target or empty_target_dir())
    return errors


def check_rule(language: str, rule_yaml: Path, empty_target: Path) -> tuple[str | None, str | None]:
    """Verify one rule. Returns (ok_line, failure); exactly one is not None.

    Pure with respect to the process: it reads files and runs semgrep, and
    touches no shared state, which is what lets rules be checked concurrently.
    The semgrep calls stay per-rule rather than batched, because rule X's
    true-positive fixture must be matched by rule X and not by rule Y.
    """
    rule_id = load_rule_id(rule_yaml)
    errors = validate_rule(rule_yaml, empty_target)
    if errors:
        return None, f"{rule_yaml}: invalid rule config: {errors[:2]}"

    tp, tn = fixtures_for_rule(rule_yaml, language)
    if tp is None:
        return None, f"{rule_yaml}: no true-positive fixture references {rule_id}"
    if tn is None:
        return None, f"{rule_yaml}: no true-negative fixture references {rule_id}"

    tp_count, tp_errors = run_semgrep(rule_yaml, tp)
    tn_count, tn_errors = run_semgrep(rule_yaml, tn)
    if tp_errors:
        return None, f"{rule_yaml} -> {tp}: semgrep errors: {tp_errors[:2]}"
    if tn_errors:
        return None, f"{rule_yaml} -> {tn}: semgrep errors: {tn_errors[:2]}"
    if tp_count < 1:
        return None, f"{rule_yaml} -> {tp}: TRUE POSITIVE produced 0 findings"
    if tn_count != 0:
        return None, f"{rule_yaml} -> {tn}: TRUE NEGATIVE produced {tn_count} findings"
    return f"OK {language}/{rule_yaml.name}: tp={tp_count} tn={tn_count}", None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-missing-semgrep",
        action="store_true",
        help="Exit 0 when semgrep is missing (for images intentionally built without semgrep).",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=None,
        help="Concurrent rule checks; defaults to the CPU count.",
    )
    args = parser.parse_args()

    if shutil.which("semgrep") is None:
        msg = "semgrep is not installed; cannot verify rule fixtures"
        if args.allow_missing_semgrep:
            print(f"SKIP: {msg}")
            return 0
        print(f"ERROR: {msg}", file=sys.stderr)
        return 2

    rules = all_rules()
    empty_target = empty_target_dir()
    # Each rule costs three semgrep process starts -- config validation, the
    # true positive and the true negative -- and semgrep's startup dominates a
    # single tiny fixture, so the wall clock was ~3x the rule count in
    # serialized process launches. The checks are independent, so they run
    # concurrently. Threads, not processes: the work is subprocess-bound and
    # the GIL is released while each semgrep runs.
    workers = max(1, min(args.jobs or (os.cpu_count() or 1), len(rules) or 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        outcomes = list(pool.map(lambda item: check_rule(*item, empty_target), rules))

    # Emitted in rule order regardless of completion order, so output and the
    # failure list stay identical to the serialized version and reviewable.
    failures = [failure for _ok, failure in outcomes if failure is not None]
    passed = 0
    for ok, _failure in outcomes:
        if ok is not None:
            passed += 1
            print(ok)

    if failures:
        print("\nRule fixture verification failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(f"\nRule fixture verification passed: {passed} rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
