"""Reviewed transitions cover exact oracle bytes and complete observed diffs."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys

import pytest
import jsonschema

ROOT = Path(__file__).resolve().parents[1]
upgrade = runpy.run_path(str(ROOT / "scripts/inventory_upgrade.py"))


def test_committed_ledger_satisfies_schema_and_strict_reader():
    path = ROOT / "evaluation/m046/accepted-upgrades.json"
    schema = json.loads((ROOT / "evaluation/m046/accepted-upgrades.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(json.loads(path.read_text()))
    assert upgrade["accepted_upgrades"](path) == json.loads(path.read_text())


@pytest.fixture
def evidence(tmp_path):
    oracle = json.loads((ROOT / "evaluation/m046/canonical-source-expectations-v1.json").read_text())
    baseline = deepcopy(oracle)
    baseline["cases"][0]["coverage"]["enumeration"] = "old-enumeration"
    raw = json.dumps(oracle).encode()
    proof = {"schema_version": "m046.canonical-source-expectations-proof/1",
             "historical_oracle_sha256": oracle["historical_oracle_sha256"],
             "expectations_sha256": hashlib.sha256(raw).hexdigest(),
             "cases": [{"case": row["case"], "observed": deepcopy(row)} for row in oracle["cases"]]}
    (tmp_path / "oracle").write_bytes(raw)
    for name, value in (("baseline", baseline), ("proof", proof), ("approvals", [])):
        (tmp_path / name).write_text(json.dumps(value))
    return tmp_path


def invoke(path, name="diff", extra=()):
    output = path / name
    result = subprocess.run([
        sys.executable, str(ROOT / "scripts/verify-inventory-upgrade.py"),
        "--baseline", str(path / "baseline"), "--candidate", str(path / "proof"),
        "--candidate-oracle", str(path / "oracle"), "--accepted-upgrades", str(path / "approvals"),
        "--output", str(output), *extra,
    ], capture_output=True, text=True)
    return result, json.loads(output.read_text())


def approve(path, report):
    entry = {**report["proposed_approval"], "reason": "Reviewed exact semantic transition", "pull_request": 162}
    (path / "approvals").write_text(json.dumps([entry]))
    return entry


def test_printed_entry_can_be_completed_and_pasted_back(evidence):
    result, report = invoke(evidence)
    assert result.returncode == 1 and report["status"] == "review-required"
    printed = json.loads(result.stdout[result.stdout.index("{"):result.stdout.rindex("}") + 1])
    assert printed == report["proposed_approval"]
    assert "reviewed pull request" in result.stdout and "1 changed cases" in result.stdout
    entry = approve(evidence, report)
    result, accepted = invoke(evidence, "accepted")
    assert result.returncode == 0 and accepted["status"] == "passed"
    assert accepted["approval"] == entry
    assert accepted["corpus"]["status"] == "review-required"  # Diff remains available for audit.
    assert accepted["candidate_sha256"] != entry["candidate_sha256"]  # Native proof vs oracle.


@pytest.mark.parametrize("field", ["baseline_sha256", "candidate_sha256", "fingerprint"])
def test_every_approval_identity_must_match_exactly(evidence, field):
    _, report = invoke(evidence)
    entry = approve(evidence, report)
    entry[field] = "0" * 64
    (evidence / "approvals").write_text(json.dumps([entry]))
    result, report = invoke(evidence, "changed")
    assert result.returncode == 1 and report["status"] == "review-required"


@pytest.mark.parametrize("change", ["baseline-bytes", "oracle-bytes", "observed-record", "missing-case", "source-corpus"])
def test_new_bytes_or_observed_semantics_cannot_reuse_approval(evidence, change):
    _, report = invoke(evidence)
    approve(evidence, report)
    if change == "baseline-bytes":
        with (evidence / "baseline").open("a") as stream:
            stream.write("\n")
    elif change == "oracle-bytes":
        raw = (evidence / "oracle").read_bytes() + b"\n"
        (evidence / "oracle").write_bytes(raw)
        proof = json.loads((evidence / "proof").read_text())
        proof["expectations_sha256"] = hashlib.sha256(raw).hexdigest()
        (evidence / "proof").write_text(json.dumps(proof))
    else:
        proof = json.loads((evidence / "proof").read_text())
        if change == "observed-record":
            proof["cases"][0]["observed"]["coverage"]["enumeration"] = "unexpected"
        elif change == "missing-case":
            proof["cases"].pop()
        else:
            proof["historical_oracle_sha256"] = "0" * 64
        (evidence / "proof").write_text(json.dumps(proof))
    result, report = invoke(evidence, "changed")
    assert result.returncode == 1 and report["status"] != "passed"


def test_architecture_and_generated_proof_metadata_do_not_change_transition(evidence):
    _, report = invoke(evidence)
    approve(evidence, report)
    proof = json.loads((evidence / "proof").read_text())
    proof.update(architecture="arm64", python_version="another-native-interpreter")
    proof["cases"].reverse()
    (evidence / "proof").write_text(json.dumps(proof))
    result, report = invoke(evidence, "arm64")
    assert result.returncode == 0 and report["approval"]["pull_request"] == 162


def test_corpus_approval_cannot_approve_new_findings(evidence):
    _, report = invoke(evidence)
    approve(evidence, report)
    (evidence / "before-findings").write_text('{"matches":[]}')
    (evidence / "after-findings").write_text('{"matches":[{"vulnerability":{"id":"new"}}]}')
    result, report = invoke(evidence, "findings", (
        "--baseline-findings", str(evidence / "before-findings"),
        "--candidate-findings", str(evidence / "after-findings"),
        "--baseline-snapshot", "a" * 64, "--candidate-snapshot", "a" * 64,
    ))
    assert result.returncode == 1 and report["status"] == "review-required"
    assert report["findings"]["status"] == "review-required"


@pytest.mark.parametrize("mutation", ["field", "digest", "reason", "number", "boolean", "duplicate", "not-list"])
def test_malformed_approval_is_refused(evidence, mutation):
    _, report = invoke(evidence)
    entry = approve(evidence, report)
    entries = [entry]
    if mutation == "field":
        entry["accept_all"] = True
    elif mutation == "digest":
        entry["fingerprint"] = "*"
    elif mutation == "reason":
        entry["reason"] = "  "
    elif mutation in {"number", "boolean"}:
        entry["pull_request"] = 0 if mutation == "number" else True
    elif mutation == "duplicate":
        entries.append(entry)
    else:
        entries = {"approvals": entries}
    (evidence / "approvals").write_text(json.dumps(entries))
    result, report = invoke(evidence, "malformed")
    assert result.returncode == 1 and report["status"] == "failed"
    assert "approval" in report["reason"]


def test_duplicate_json_keys_are_refused(evidence):
    (evidence / "approvals").write_text('[{"reason":"first","reason":"second"}]')
    result, report = invoke(evidence)
    assert result.returncode == 1 and "duplicate-json-key" in report["reason"]


def test_missing_or_spoofed_oracle_digest_is_refused(evidence):
    proof = json.loads((evidence / "proof").read_text())
    proof["expectations_sha256"] = "0" * 64
    (evidence / "proof").write_text(json.dumps(proof))
    result, report = invoke(evidence)
    assert result.returncode == 1 and report["reason"] == "upgrade-candidate-oracle-digest-mismatch"
