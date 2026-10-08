"""Canonical snapshot agreement without promoting parsing into execution proof."""

import hashlib

import pytest

from sourcebastion.inventory.contract import (
    Coverage,
    InputCoverage,
    InventoryLimits,
    ProjectionLoss,
    Relationship,
    StageStates,
    canonical_bytes,
    identifier,
)
from sourcebastion.inventory.summary_projection import ProjectionError, project_inventory
from tests.test_inventory_contract import inventory, locator, occurrence


def project(value, check=lambda: None):
    return project_inventory(value, check=check)


def test_format_identification_is_distinct_from_supported_or_parsed():
    coverage = Coverage(
        discovery="partial",
        enumeration="partial",
        version_resolution="unknown",
        graph="unknown",
        environment="unknown",
        inputs=(
            InputCoverage(
                source_path="custom.lock",
                source_sha256="a" * 64,
                format="unsupported-example",
                parser=None,
                disposition="unsupported",
                reason="unsupported-format",
            ),
            InputCoverage(
                source_path="broken.txt",
                source_sha256="b" * 64,
                format="pip-requirements",
                parser="pip-requirements/1",
                disposition="failed",
                reason="invalid-input",
            ),
            InputCoverage(
                source_path="missing.txt",
                source_sha256=None,
                format=None,
                parser=None,
                disposition="unresolved",
                reason="missing-reference",
            ),
        ),
    )
    value = inventory(coverage=coverage, stages=StageStates(inventory="partial"))
    facts = project(value)["inventory"]
    assert facts["counts"]["discovered_inputs"] == 3
    assert facts["counts"]["recognized_inputs"] == 2
    assert facts["counts"]["input_dispositions"] == {
        "discovered": 0,
        "parsed": 0,
        "ignored": 0,
        "unsupported": 1,
        "failed": 1,
        "bounded-omission": 0,
        "unresolved": 1,
    }
    assert facts["canonical_state"] == "partial"
    assert facts["coverage"]["enumeration"] == "partial"


def test_conditional_evidenced_edges_and_canonical_losses_are_preserved():
    parent, child = occurrence("a.txt"), occurrence("b.txt")
    edge = Relationship(
        id=identifier("relationship", "conditional"),
        parent_id=parent.id,
        child_id=child.id,
        source=locator("a.txt"),
        evidence_status="evidenced",
        activation="unknown",
        marker='python_version < "3.12"',
        extras=("socks",),
    )
    loss = ProjectionLoss(
        id=identifier("loss", "conditional"),
        source=edge.source,
        dimension="graph",
        reason="conditional-edge",
        relationship_id=edge.id,
    )
    value = inventory(occurrences=(parent, child), relationships=(edge,), losses=(loss,))
    facts = project(value)
    assert facts["inventory"]["counts"]["canonical_relationships"] == 1
    assert facts["inventory"]["counts"]["evidenced_relationships"] == 1
    assert facts["inventory"]["counts"]["canonical_projection_losses"] == 1
    assert "export" not in facts and "matching" not in facts
    assert "execution" not in facts["inventory"]


def test_unselected_occurrence_is_not_selected_by_name_or_declared_presence():
    row = occurrence(purl=None, selected_version=None)
    base = inventory()
    coverage = base.coverage.model_copy(update={"version_resolution": "partial"})
    value = inventory(occurrences=(row,), coverage=coverage, stages=StageStates(inventory="partial"))
    counts = project(value)["inventory"]["counts"]
    assert counts["package_occurrences"] == 1 and counts["selected_occurrences"] == 0


def test_artifact_and_all_facts_use_one_detached_snapshot():
    value = inventory(occurrences=(occurrence(),))
    expected = canonical_bytes(value)
    calls = 0

    def change_original_after_snapshot():
        nonlocal calls
        calls += 1
        if calls == 2:
            object.__setattr__(value, "occurrences", ())

    facts = project(value, change_original_after_snapshot)
    assert facts["inventory"]["counts"]["package_occurrences"] == 1
    assert facts["inventory"]["artifact"] == {
        "format": "sourcebastion.inventory/1",
        "sha256": hashlib.sha256(expected).hexdigest(),
        "byte_count": len(expected),
    }
    assert value.occurrences == ()


def test_reordering_equivalent_typed_input_preserves_projection_and_digest():
    a, b = occurrence("a.txt"), occurrence("b.txt")
    assert project(inventory(occurrences=(a, b))) == project(inventory(occurrences=(b, a)))


def test_returned_maps_are_detached_and_confer_no_execution_identity():
    value = inventory()
    facts = project(value)
    facts["inventory"]["producer"]["name"] = "changed"
    facts["inventory"]["coverage"]["discovery"] = "failed"
    fresh = project(value)
    assert fresh["inventory"]["producer"]["name"] == "test-controller"
    assert fresh["inventory"]["coverage"]["discovery"] == "complete"
    assert set(fresh) == {"projection_version", "source_sha256", "inventory"}
    assert "scanner_image" not in fresh and "plan_digest" not in fresh


@pytest.mark.parametrize("value", [b"{}", {}, None, "untrusted.json"])
def test_raw_values_are_refused_without_echo(value):
    with pytest.raises(ProjectionError, match="^inventory_projection_invalid$"):
        project(value)


def test_unvalidated_model_copy_is_revalidated_without_detail_leak():
    value = inventory().model_copy(update={"source_sha256": "SECRET-PATH"})
    with pytest.raises(ProjectionError) as error:
        project(value)
    assert str(error.value) == "inventory_projection_invalid" and error.value.__cause__ is None


def test_existing_canonical_output_limits_are_not_widened():
    value = inventory(limits=InventoryLimits(inventory_bytes=1))
    with pytest.raises(ProjectionError, match="^inventory_projection_invalid$"):
        project(value)


@pytest.mark.parametrize("cancel_at", range(1, 6))
def test_shared_cancellation_propagates_before_return(cancel_at):
    failure = RuntimeError("trusted-cancel")
    calls = 0

    def check():
        nonlocal calls
        calls += 1
        if calls == cancel_at:
            raise failure

    with pytest.raises(RuntimeError) as error:
        project(inventory(occurrences=(occurrence(),)), check)
    assert error.value is failure and calls == cancel_at
