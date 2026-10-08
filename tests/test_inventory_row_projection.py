"""Pure row projection boundaries; no scanner execution or storage assertions."""

from dataclasses import FrozenInstanceError
import hashlib
import json

import pytest

from sourcebastion.inventory.contract import (
    AnalysisScope,
    Declaration,
    InventoryLimits,
    ProjectionLoss,
    Relationship,
    Root,
    StageStates,
    canonical_bytes,
    identifier,
)
from sourcebastion.inventory.row_projection import (
    RowProjectionError,
    project_rows,
)
from tests.test_inventory_contract import inventory, locator, occurrence


def project(value, **kwargs):
    return project_rows(
        value,
        max_rows=kwargs.pop("max_rows", 1000),
        max_bytes=kwargs.pop("max_bytes", 1024**2),
        check=kwargs.pop("check", lambda: None),
        **kwargs,
    )


def table(projection, name):
    return [row for row in projection.rows if row.table == name]


def test_equal_packages_remain_distinct_across_roots():
    roots = tuple(
        Root(id=identifier("root", path), path=path, source=locator(path + "/requirements.txt")) for path in ("a", "b")
    )
    rows = tuple(occurrence(root.path + "/requirements.txt", root_id=root.id) for root in roots)
    result = project(inventory(roots=roots, occurrences=rows))
    stored = table(result, "occurrence")
    assert len(stored) == 2 and len({row.key for row in stored}) == 2
    assert len({dict(row.columns)["purl"] for row in stored}) == 1
    assert {dict(row.columns)["root_id"] for row in stored} == {r.id for r in roots}


def test_recorded_lexical_versions_and_null_last_have_unique_ranks():
    rows = (
        occurrence("a.txt", selected_version="9.0", purl="pkg:pypi/pip@9.0"),
        occurrence("b.txt", selected_version="10.0", purl="pkg:pypi/pip@10.0"),
        occurrence("c.txt", selected_version=None, purl=None),
        occurrence("d.txt", selected_version="9.0", purl="pkg:pypi/pip@9.0"),
    )
    complete = inventory(occurrences=(rows[0], rows[1], occurrence("c.txt"), rows[3]))
    base = complete.model_copy(
        update={
            "occurrences": rows,
            "stages": StageStates(inventory="partial"),
            "coverage": complete.coverage.model_copy(update={"version_resolution": "partial"}),
        }
    )
    result = project(base)
    ordered = sorted(table(result, "occurrence"), key=lambda r: dict(r.columns)["name_version_rank"])
    assert [dict(r.columns)["selected_version"] for r in ordered] == ["10.0", "9.0", "9.0", None]
    assert [dict(r.columns)["name_version_rank"] for r in ordered] == list(range(4))
    assert ordered[1].key < ordered[2].key


def test_canonical_evidence_edges_losses_and_facets_are_preserved():
    parent = occurrence("a.txt", scopes=("development",), extras=("socks",))
    child = occurrence("b.txt")
    edge = Relationship(
        id=identifier("relationship", "edge"),
        parent_id=parent.id,
        child_id=child.id,
        source=locator("a.txt"),
        evidence_status="unassessed",
        activation="unknown",
    )
    loss = ProjectionLoss(
        id=identifier("loss", "edge"),
        source=locator("a.txt"),
        dimension="graph",
        reason="conditional-edge",
        relationship_id=edge.id,
    )
    decl = Declaration(
        id=identifier("declaration", "decl"), source=locator("a.txt"), kind="requirement", ecosystem="pypi", name="pip"
    )
    result = project(
        inventory(occurrences=(parent, child), relationships=(edge,), declarations=(decl,), losses=(loss,))
    )
    assert json.loads(table(result, "relationship")[0].detail)["evidence_status"] == "unassessed"
    evidence = {r.key[0]: json.loads(r.detail) for r in table(result, "evidence")}
    assert evidence["loss"]["relationship_id"] == edge.id
    assert evidence["declaration"]["name"] == "pip"
    facets = {(dict(r.columns)["facet"], dict(r.columns)["value"]) for r in table(result, "occurrence_facet")}
    assert facets == {("scopes", "development"), ("extras", "socks")}


def test_multi_context_input_is_one_global_input_without_ecosystem_inference():
    roots = tuple(Root(id=identifier("root", path), path=path, source=locator()) for path in ("a", "b"))
    scope = AnalysisScope(id=identifier("scope", "analysis"), kind="manifest-input", source=locator())
    value = inventory(roots=roots, analysis_scopes=(scope,))
    covered = value.coverage.inputs[0].model_copy(
        update={
            "root_ids": tuple(r.id for r in roots),
            "analysis_scope_ids": (scope.id,),
        }
    )
    value = value.model_copy(update={"coverage": value.coverage.model_copy(update={"inputs": (covered,)})})
    result = project(value)
    assert len(table(result, "input")) == 1 and len(table(result, "input_context")) == 3
    assert dict(table(result, "snapshot")[0].columns)["input_count"] == 1
    assert not table(result, "input_ecosystem") and not table(result, "matches")
    assert json.loads(table(result, "snapshot")[0].detail)["coverage"]["environment"] == "unknown"


def test_unknown_context_stays_unknown_and_empty_is_not_a_ready_receipt():
    result = project(inventory())
    assert not table(result, "input_context") and not table(result, "occurrence")
    assert "ready" not in dict(table(result, "snapshot")[0].columns)
    assert not hasattr(result, "account_id") and not hasattr(result, "matching")


def test_equivalent_canonical_reordering_preserves_rows_and_digest():
    a, b = occurrence("a.txt"), occurrence("b.txt")
    assert project(inventory(occurrences=(a, b))) == project(inventory(occurrences=(b, a)))


def test_exact_logical_row_and_byte_limits_refuse_one_less():
    value = inventory(occurrences=(occurrence(scopes=("development",)),))
    expected = project(value)
    assert project(value, max_rows=len(expected.rows), max_bytes=expected.logical_bytes) == expected
    with pytest.raises(RowProjectionError, match="^inventory_row_count_limit$"):
        project(value, max_rows=len(expected.rows) - 1)
    with pytest.raises(RowProjectionError, match="^inventory_row_byte_limit$"):
        project(value, max_bytes=expected.logical_bytes - 1)


def test_projection_hash_uses_a_separate_framed_domain():
    value = inventory(occurrences=(occurrence(),))
    result = project(value)
    assert result.inventory_sha256 == hashlib.sha256(canonical_bytes(value)).hexdigest()
    assert result.projection_sha256 != result.inventory_sha256

    def encode(obj):
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()

    def frame(raw):
        return len(raw).to_bytes(8, "big") + raw

    raw = (
        result.projection_version.encode()
        + b"\0"
        + frame(
            encode(
                {
                    "projection_version": result.projection_version,
                    "inventory_sha256": result.inventory_sha256,
                    "source_sha256": result.source_sha256,
                }
            )
        )
    )
    for row in result.rows:
        raw += frame(encode({"table": row.table, "key": row.key, "columns": row.columns})) + frame(row.detail)
    assert len(raw) == result.logical_bytes
    assert hashlib.sha256(raw).hexdigest() == result.projection_sha256


def test_original_mutation_after_snapshot_cannot_change_digest_or_rows():
    value = inventory(occurrences=(occurrence(),))
    expected = canonical_bytes(value)
    calls = 0

    def mutate():
        nonlocal calls
        calls += 1
        if calls == 2:
            object.__setattr__(value, "occurrences", ())

    result = project(value, check=mutate)
    assert result.inventory_sha256 == hashlib.sha256(expected).hexdigest()
    assert len(table(result, "occurrence")) == 1 and value.occurrences == ()
    with pytest.raises(FrozenInstanceError):
        result.rows[0].detail = b"changed"


@pytest.mark.parametrize("value", [b"{}", {}, None, "secret-path"])
def test_raw_values_are_refused_without_echo(value):
    with pytest.raises(RowProjectionError, match="^inventory_row_projection_invalid$"):
        project(value)


@pytest.mark.parametrize(
    "limits", [dict(max_rows=True), dict(max_rows=0), dict(max_bytes=0), dict(max_bytes=2**63), dict(max_rows="1")]
)
def test_caller_limits_are_exact_positive_integers(limits):
    with pytest.raises(RowProjectionError, match="^inventory_row_limits_invalid$"):
        project(inventory(), **limits)


def test_unvalidated_model_and_canonical_limit_refuse_with_fixed_diagnostic():
    for value in (
        inventory().model_copy(update={"source_sha256": "SECRET"}),
        inventory(limits=InventoryLimits(inventory_bytes=1)),
    ):
        with pytest.raises(RowProjectionError) as failure:
            project(value)
        assert str(failure.value) == "inventory_row_projection_invalid" and failure.value.__cause__ is None


@pytest.mark.parametrize("cancel_at", range(1, 11))
def test_shared_cancellation_propagates_without_partial_return(cancel_at):
    failure = RuntimeError("trusted-cancel")
    calls = 0

    def check():
        nonlocal calls
        calls += 1
        if calls == cancel_at:
            raise failure

    with pytest.raises(RuntimeError) as caught:
        project(inventory(occurrences=(occurrence(scopes=("dev",)),)), check=check)
    assert caught.value is failure and calls == cancel_at
