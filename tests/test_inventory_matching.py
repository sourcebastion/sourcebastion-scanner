"""Exact occurrence joins, original findings and separate stage failures."""

from dataclasses import replace
import hashlib
import json
import time

import pytest

from sourcebastion.inventory.contract import InventoryLimits, StageStates, canonical_bytes
from sourcebastion.inventory.cyclonedx import export
from sourcebastion.inventory.inputs import InputRefusal
from sourcebastion.inventory.matching import Consumer, recover
from tests.test_inventory_contract import inventory, occurrence


def consumer(**updates):
    return Consumer(
        **(
            {
                "binary_sha256": "a" * 64,
                "version": "0.119.0",
                "config_sha256": "b" * 64,
                "advisory_snapshot_sha256": "c" * 64,
                "advisory_schema": "v6.1.10",
                "advisory_built": "2026-10-06T06:32:14Z",
            }
            | updates
        )
    )


def report(rows):
    return {
        "matches": [
            {
                "artifact": {
                    "id": row.id,
                    "type": "python",
                    "name": row.name,
                    "version": row.selected_version,
                    "purl": row.purl,
                    "locations": None,
                },
                "vulnerability": {
                    "id": "GHSA-test",
                    "namespace": "github:language:python",
                    "severity": "Medium",
                    "fix": {"versions": ["26.2"], "state": "fixed"},
                    "cvss": [{"metrics": {"baseScore": 5.5}}],
                    "epss": [{"epss": 0.2}],
                },
                "matchDetails": [{"matcher": "python-matcher"}],
            }
            for row in rows
        ],
        "source": {"type": "sbom-file"},
        "descriptor": {
            "name": "grype",
            "version": "0.119.0",
            "db": {"status": {"schemaVersion": "v6.1.10", "built": "2026-10-06T06:32:14Z", "valid": True}},
        },
    }


def invoke(value, payload, *, artifact=None, **kwargs):
    deadline = kwargs.pop("deadline", time.monotonic() + 10)
    artifact = artifact or export(value, deadline=deadline, check=lambda: None)
    raw = payload if type(payload) is bytes else json.dumps(payload, indent=2).encode()
    return recover(
        value,
        artifact,
        raw,
        consumer=kwargs.pop("consumer", consumer()),
        deadline=deadline,
        check=kwargs.pop("check", lambda: None),
        **kwargs,
    )


def test_duplicate_purls_keep_exact_context_and_original_finding_bytes():
    rows = (occurrence("one/requirements.txt"), occurrence("two/requirements.txt"))
    value = inventory(occurrences=rows)
    before = canonical_bytes(value)
    original = json.dumps(report(rows + rows[:1]), indent=2).encode()
    result = invoke(value, original)
    assert result.original_output == original and result.output_sha256 == hashlib.sha256(original).hexdigest()
    assert [row.occurrence_id for row in result.matches] == [rows[0].id, rows[1].id, rows[0].id]
    assert len(result.occurrence_contexts) == 2
    assert {json.loads(raw)["source"]["path"] for _, raw in result.occurrence_contexts} == {
        "one/requirements.txt",
        "two/requirements.txt",
    }
    assert all(json.loads(raw)["activation"] == "unknown" for _, raw in result.occurrence_contexts)
    assert canonical_bytes(value) == before and value.stages.export == value.stages.matching == "not-run"


@pytest.mark.parametrize(
    "field,wrong",
    [("id", "unknown"), ("type", "npm"), ("name", "other"), ("version", "26.2"), ("purl", "pkg:pypi/other@26.0.1")],
)
def test_no_name_or_purl_fallback_for_unknown_or_contradictory_id(field, wrong):
    row = occurrence()
    payload = report((row,))
    payload["matches"][0]["artifact"][field] = wrong
    with pytest.raises(ValueError):
        invoke(inventory(occurrences=(row,)), payload)


def test_unversioned_range_is_not_an_exported_matching_target():
    row = occurrence(selected_version=None, purl="pkg:pypi/pip", declared_range=">=20")
    value = inventory(
        occurrences=(row,),
        stages=StageStates(inventory="partial"),
        coverage=inventory().coverage.model_copy(update={"version_resolution": "partial"}),
    )
    assert not invoke(value, report(())).matches
    with pytest.raises(ValueError, match="unknown-matching-occurrence"):
        invoke(value, report((row,)))


def test_partial_inventory_can_match_without_promoting_inventory_coverage():
    row = occurrence()
    value = inventory(occurrences=(row,), stages=StageStates(inventory="partial"))
    assert invoke(value, report((row,))).matching == "succeeded"
    assert value.stages.inventory == "partial" and value.coverage == inventory().coverage


@pytest.mark.parametrize(
    "field,value",
    [
        ("content", b"{}"),
        ("sha256", "0" * 64),
        ("identity_sha256", "0" * 64),
        ("omitted_occurrences", 5),
        ("scope_losses", 0),
    ],
)
def test_forged_export_receipt_is_not_admission(field, value):
    row = occurrence()
    inv = inventory(occurrences=(row,))
    artifact = export(inv, deadline=time.monotonic() + 10, check=lambda: None)
    with pytest.raises(ValueError, match="matching-artifact-canonical-binding-mismatch"):
        invoke(inv, report((row,)), artifact=replace(artifact, **{field: value}))


@pytest.mark.parametrize(
    "raw",
    [
        b'{"matches":[],"matches":[]}',
        b'{"matches":[],"x":NaN}',
        b'{"matches":[],"x":1e999}',
        b"\xff",
        b"[]",
        b"{}",
        b"{",
    ],
)
def test_invalid_or_incomplete_report_is_not_zero_vulnerabilities(raw):
    with pytest.raises(ValueError):
        invoke(inventory(), raw)


@pytest.mark.parametrize(
    "path,value",
    [
        (("name",), "other"),
        (("version",), "0.1"),
        (("db", "status", "valid"), False),
        (("db", "status", "schemaVersion"), "v5"),
        (("db", "status", "built"), "other"),
    ],
)
def test_consumer_and_advisory_report_identity_must_match_controller(path, value):
    payload = report(())
    target = payload["descriptor"]
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValueError):
        invoke(inventory(), payload)


def test_matching_failure_preserves_admitted_inventory_and_artifact():
    row = occurrence()
    value = inventory(occurrences=(row,))
    before = canonical_bytes(value)
    artifact = export(value, deadline=time.monotonic() + 10, check=lambda: None)
    with pytest.raises(ValueError):
        invoke(value, b'{"matches":[]}', artifact=artifact)
    assert canonical_bytes(value) == before and artifact.sha256 == hashlib.sha256(artifact.content).hexdigest()


def test_remaining_deadline_and_shared_ledger_are_enforced():
    value = inventory()
    artifact = export(value, deadline=time.monotonic() + 10, check=lambda: None)
    with pytest.raises(InputRefusal, match="deadline"):
        invoke(value, report(()), artifact=artifact, deadline=time.monotonic() - 1)

    def exhausted():
        raise InputRefusal("shared-work-exhausted")

    with pytest.raises(InputRefusal, match="shared-work-exhausted"):
        invoke(value, report(()), artifact=artifact, check=exhausted)


def test_identity_changes_when_any_controller_consumer_identity_changes():
    value = inventory()
    raw = report(())
    original = invoke(value, raw)
    for key in ("binary_sha256", "config_sha256", "advisory_snapshot_sha256"):
        assert invoke(value, raw, consumer=consumer(**{key: "d" * 64})).identity_sha256 != original.identity_sha256


def test_report_predecode_depth_and_bytes_are_bounded():
    with pytest.raises(InputRefusal, match="depth-budget"):
        invoke(inventory(), b"[" * 40 + b"]" * 40)
    value = inventory(limits=InventoryLimits(diagnostic_file_bytes=20))
    with pytest.raises(InputRefusal, match="byte-budget"):
        invoke(value, report(()))
