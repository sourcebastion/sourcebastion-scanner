"""Constraint and source-version links cannot confer unrelated package authority."""

import pytest
from pydantic import ValidationError

from sourcebastion.inventory.contract import (
    AnalysisScope,
    Applicability,
    Coverage,
    Declaration,
    Environment,
    InputCoverage,
    InputReference,
    Inventory,
    Locator,
    Occurrence,
    Producer,
    StageStates,
    identifier,
)

SHA = "a" * 64
SOURCE = Locator(path="requirements.txt", source_sha256=SHA, locator="line:1", parser="test/1")
SCOPE = AnalysisScope(id=identifier("scope", "origin"), kind="requirements-origin", source=SOURCE)


def declaration(**changes):
    data = dict(
        id=identifier("declaration", "pin"),
        source=SOURCE,
        kind="constraint",
        ecosystem="pypi",
        name="pip",
        declared_range="==26.0.1",
        exact_version="26.0.1",
        analysis_scope_id=SCOPE.id,
    )
    data.update(changes)
    return Declaration(**data)


def occurrence(**changes):
    data = dict(
        id=identifier("occurrence", "pip"),
        source=SOURCE,
        ecosystem="pypi",
        name="pip",
        evidence_kind="declared",
        selected_version="26.0.1",
        purl="pkg:pypi/pip@26.0.1",
        analysis_scope_id=SCOPE.id,
        selection_declaration_ids=(identifier("declaration", "pin"),),
    )
    data.update(changes)
    return Occurrence(**data)


def inventory(**changes):
    environment = Environment()
    data = dict(
        source_sha256=SHA,
        producer=Producer(name="test", version="1", code_sha256=SHA, registry_sha256=SHA, config_sha256=SHA),
        environment=environment,
        environment_sha256=environment.sha256,
        analysis_scopes=(SCOPE,),
        coverage=Coverage(
            discovery="complete",
            enumeration="complete",
            version_resolution="complete",
            graph="unknown",
            environment="unknown",
            inputs=(
                InputCoverage(
                    source_path=SOURCE.path,
                    source_sha256=SHA,
                    format="pip-requirements",
                    parser="test/1",
                    disposition="parsed",
                    reason="test",
                ),
            ),
        ),
        stages=StageStates(inventory="complete"),
    )
    data.update(changes)
    return Inventory(**data)


def test_constraints_are_separate_records_and_selection_is_bound():
    pin = declaration()
    record = inventory(declarations=(pin,), occurrences=(occurrence(),))
    assert len(record.occurrences) == 1 and record.declarations[0].kind == "constraint" and not record.relationships
    with pytest.raises(ValidationError, match="selection-evidence"):
        inventory(occurrences=(occurrence(),))


@pytest.mark.parametrize(
    "changes", [dict(name="setuptools"), dict(analysis_scope_id=None), dict(scopes=("build",)), dict(groups=("test",))]
)
def test_selection_cannot_borrow_another_identity_or_context(changes):
    with pytest.raises(ValidationError, match="contradictory-selection-context"):
        inventory(declarations=(declaration(**changes),), occurrences=(occurrence(),))


def test_selection_requires_a_compatible_actual_exact_source_pin():
    with pytest.raises(ValidationError, match="exact-source-evidence"):
        inventory(declarations=(declaration(declared_range=">=26", exact_version=None),), occurrences=(occurrence(),))
    other = declaration(id=identifier("declaration", "range"), declared_range=">=27", exact_version=None)
    row = occurrence(selection_declaration_ids=(declaration().id, other.id))
    with pytest.raises(ValidationError, match="contradictory-selection-range"):
        inventory(declarations=(declaration(), other), occurrences=(row,))
    with pytest.raises(ValidationError, match="contradictory-declaration-version"):
        declaration(declared_range=">=27")


def test_selection_links_cannot_remain_on_an_unselected_occurrence():
    row = occurrence(selected_version=None, purl="pkg:pypi/pip")
    coverage = inventory().coverage.model_copy(update={"version_resolution": "partial"})
    with pytest.raises(ValidationError, match="requires-selected-version"):
        inventory(
            declarations=(declaration(),),
            occurrences=(row,),
            coverage=coverage,
            stages=StageStates(inventory="partial"),
        )


def test_input_references_bind_target_coverage_and_scope_without_becoming_edges():
    values = dict(
        id=identifier("input-reference", "include"),
        source=SOURCE,
        analysis_scope_id=SCOPE.id,
        kind="include",
        role="constraint",
        target_path=SOURCE.path,
        target_sha256=SHA,
        disposition="parsed",
        reason="test",
    )
    reference = InputReference(**values)
    assert inventory(input_references=(reference,)).input_references[0].role == "constraint"
    for changes in (dict(target_path="missing.in"), dict(target_sha256="b" * 64)):
        with pytest.raises(ValidationError, match="reference-target"):
            inventory(input_references=(reference.model_copy(update=changes),))
    with pytest.raises(ValidationError):
        InputReference(**{**values, "target_path": "../outside.in"})
    with pytest.raises(ValidationError, match="reference-context"):
        inventory(
            input_references=(reference.model_copy(update={"analysis_scope_id": identifier("scope", "missing")}),)
        )


def test_applicability_retains_unknown_owner_and_refuses_false_dialect_or_context():
    condition = Applicability(
        id=identifier("applicability", "python"),
        source=SOURCE,
        kind="python-version",
        dialect="pep440",
        expression=">=3.12",
        analysis_scope_id=SCOPE.id,
    )
    assert inventory(applicability=(condition,)).applicability[0].root_id is None
    with pytest.raises(ValidationError, match="applicability-dialect"):
        Applicability.model_validate(condition.model_copy(update={"dialect": "pep508"}))
    with pytest.raises(ValidationError, match="applicability-context"):
        inventory(applicability=(condition.model_copy(update={"root_id": identifier("root", "missing")}),))


@pytest.mark.parametrize(
    "field,record",
    [
        ("declarations", declaration()),
        (
            "input_references",
            InputReference(
                id=identifier("input-reference", "x"),
                source=SOURCE,
                analysis_scope_id=SCOPE.id,
                kind="include",
                role="requirement",
                target_path=None,
                target_sha256=None,
                disposition="failed",
                reason="outside-source",
            ),
        ),
        (
            "applicability",
            Applicability(
                id=identifier("applicability", "x"),
                source=SOURCE,
                kind="marker",
                dialect="pep508",
                expression='os_name == "posix"',
            ),
        ),
    ],
)
def test_each_new_evidence_class_requires_read_hash_bound_source_coverage(field, record):
    bad_source = SOURCE.model_copy(update={"source_sha256": "b" * 64})
    with pytest.raises(ValidationError, match="unbound-source-coverage"):
        inventory(**{field: (record.model_copy(update={"source": bad_source}),)})


def test_parsed_reference_requires_a_read_target_with_parsed_or_unresolved_coverage():
    data = dict(
        id=identifier("input-reference", "parsed"),
        source=SOURCE,
        analysis_scope_id=SCOPE.id,
        kind="include",
        role="requirement",
        target_path=SOURCE.path,
        target_sha256=SHA,
        disposition="parsed",
        reason="test",
    )
    for changes in (dict(target_path=None, target_sha256=None), dict(target_sha256=None)):
        with pytest.raises(ValidationError, match="parsed-reference-requires-read-target"):
            InputReference(**{**data, **changes})
    reference = InputReference(**data)
    for disposition in ("ignored", "failed", "unsupported", "bounded-omission", "discovered"):
        coverage = inventory().coverage
        changed = coverage.inputs[0].model_copy(update={"disposition": disposition})
        with pytest.raises(ValidationError, match="parsed-reference-requires-parsed-target"):
            inventory(input_references=(reference,), coverage=coverage.model_copy(update={"inputs": (changed,)}))
    coverage = inventory().coverage
    unresolved = coverage.inputs[0].model_copy(update={"disposition": "unresolved", "reason": "no-selected-version"})
    assert inventory(
        input_references=(reference,),
        coverage=coverage.model_copy(update={"inputs": (unresolved,)}),
        stages=StageStates(inventory="partial"),
    ).input_references == (reference,)
