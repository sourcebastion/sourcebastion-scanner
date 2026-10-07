"""Canonical authority, separate stages and offline standard export fidelity."""

import hashlib
import importlib.util
import json
from pathlib import Path
import time

import pytest
from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry, Resource

from sourcebastion.inventory.cyclonedx import export, SCHEMAS, PREFIX
from sourcebastion.inventory.contract import InventoryLimits, Relationship, StageStates, identifier
from sourcebastion.inventory.inputs import InputRefusal
from tests.test_inventory_contract import inventory, occurrence, locator


def emit(value, **kwargs):
    return export(
        value, deadline=kwargs.pop("deadline", time.monotonic() + 10), check=kwargs.pop("check", lambda: None), **kwargs
    )


@pytest.fixture(scope="module")
def standard():
    def no_remote(uri):
        raise ValueError("remote-schema-retrieval-refused")

    root = Path(__file__).resolve().parents[1] / "evaluation/m046/cyclonedx-schemas"
    registry, documents = Registry(retrieve=no_remote), {}
    for name, checksum in SCHEMAS.items():
        raw = (root / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == checksum
        schema = json.loads(raw)
        documents[name] = schema
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return Draft7Validator(documents["bom-1.6.schema.json"], registry=registry, format_checker=FormatChecker())


def props(rows):
    return [(row["name"].removeprefix(PREFIX), json.loads(row["value"])) for row in rows]


def test_custom_input_exact_source_and_separate_stage_state(standard):
    selected = occurrence("locks/custom.pin")
    value = inventory(occurrences=(selected,))
    before = value.model_dump()
    artifact = emit(value)
    document = json.loads(artifact.content)
    standard.validate(document)
    assert artifact.sha256 == hashlib.sha256(artifact.content).hexdigest()
    assert value.model_dump() == before and value.stages.export == value.stages.matching == "not-run"
    (component,) = document["components"]
    assert (component["bom-ref"], component["purl"], component["version"]) == (selected.id, selected.purl, "26.0.1")
    assert component["evidence"]["occurrences"] == [
        {"location": "locks/custom.pin", "additionalContext": "line:1", "line": 1}
    ]
    assert props(component["properties"]) == [
        ("occurrence", selected.model_dump(mode="json")),
        ("projection-losses", ["cyclonedx-default-required-scope-unassessed"]),
    ]
    assert artifact.scope_losses == 1 and "scope" not in component
    assert "dependencies" not in document and document["compositions"] == [{"aggregate": "unknown"}]


def test_equal_purls_in_different_sources_keep_occurrence_identity(standard):
    rows = (occurrence("one/requirements.txt"), occurrence("two/requirements.txt"))
    value = inventory(occurrences=rows)
    document = json.loads(emit(value).content)
    standard.validate(document)
    assert len(document["components"]) == 2
    assert len({row["bom-ref"] for row in document["components"]}) == 2
    assert len({row["purl"] for row in document["components"]}) == 1
    assert emit(value).content == emit(inventory(occurrences=tuple(reversed(rows)))).content


def test_unresolved_occurrence_stays_metadata_not_matching_target(standard):
    row = occurrence(selected_version=None, purl="pkg:pypi/pip", declared_range=">=20")
    value = inventory(
        occurrences=(row,),
        stages=StageStates(inventory="partial"),
        coverage=inventory().coverage.model_copy(update={"version_resolution": "partial"}),
    )
    artifact = emit(value)
    document = json.loads(artifact.content)
    standard.validate(document)
    assert not document["components"] and artifact.omitted_occurrences == 1
    assert ("unexported-occurrence", row.model_dump(mode="json")) in props(document["metadata"]["properties"])


@pytest.mark.parametrize(
    "ecosystem,name,version",
    [
        ("npm", "@scope/package", "1.2.3"),
        ("golang", "example.invalid/module", "v1.2.3"),
        ("cargo", "crate", "1.2.3"),
        ("maven", "org.example/package", "1.2.3"),
        ("nuget", "package", "1.2.3"),
        ("gem", "package", "1.2.3"),
        ("composer", "vendor/package", "1.2.3"),
    ],
)
def test_canonical_ecosystem_identity_is_preserved(standard, ecosystem, name, version):
    from sourcebastion.inventory.contract import package_purl

    row = occurrence(
        ecosystem=ecosystem, name=name, selected_version=version, purl=package_purl(ecosystem, name, version)
    )
    document = json.loads(emit(inventory(occurrences=(row,))).content)
    standard.validate(document)
    assert document["components"][0]["purl"] == row.purl


@pytest.mark.parametrize(
    "activation,marker,extras,emitted",
    [
        ("active", None, (), True),
        ("unknown", None, (), False),
        ("inactive", None, (), False),
        ("active", 'python_version < "4"', (), False),
        ("active", None, ("optional",), False),
    ],
)
def test_only_evidenced_unconditional_active_edges_are_projected(standard, activation, marker, extras, emitted):
    parent = occurrence("requirements.txt", activation="active")
    child = occurrence("other.txt", activation="active")
    edge = Relationship(
        id=identifier("relationship", [activation, marker, extras]),
        parent_id=parent.id,
        child_id=child.id,
        source=locator(),
        evidence_status="evidenced",
        activation=activation,
        marker=marker,
        extras=extras,
    )
    artifact = emit(inventory(occurrences=(parent, child), relationships=(edge,)))
    document = json.loads(artifact.content)
    standard.validate(document)
    assert ("dependencies" in document) is emitted
    assert artifact.omitted_relationships == (0 if emitted else 1)
    if emitted:
        assert document["dependencies"] == [{"ref": parent.id, "dependsOn": [child.id]}]
    assert ("relationships", edge.model_dump(mode="json")) in props(document["metadata"]["properties"])


def test_failed_inventory_refuses_without_promotion():
    value = inventory(stages=StageStates(inventory="failed"))
    with pytest.raises(ValueError, match="failed-inventory"):
        emit(value)
    assert value.stages.export == "not-run"


def test_unvalidated_model_copy_cannot_forge_selected_identity():
    row = occurrence().model_copy(update={"purl": "pkg:pypi/other@1.0"})
    value = inventory().model_copy(update={"occurrences": (row,)})
    with pytest.raises(ValueError):
        emit(value)


@pytest.mark.parametrize("field,budget", [("sbom_bytes", 100), ("export_string_bytes", 600), ("export_nodes", 100)])
def test_output_refuses_atomically_under_controller_limits(field, budget):
    value = inventory(occurrences=(occurrence(),), limits=InventoryLimits(**{field: budget}))
    with pytest.raises((InputRefusal, ValueError)):
        emit(value)
    assert value.stages.export == "not-run"


def test_remaining_deadline_and_shared_ledger_refusals_propagate():
    with pytest.raises(InputRefusal, match="deadline"):
        emit(inventory(), deadline=time.monotonic() - 1)

    def exhausted():
        raise InputRefusal("composition-check-budget-exceeded")

    with pytest.raises(InputRefusal, match="composition-check-budget-exceeded"):
        emit(inventory(), check=exhausted)


@pytest.mark.parametrize("scope", ["unknown", "dev", "build", "runtime"])
def test_source_scope_cannot_silently_become_required_runtime(scope, standard):
    value = inventory(occurrences=(occurrence(scopes=(scope,), activation="unknown"),))
    artifact = emit(value)
    document = json.loads(artifact.content)
    standard.validate(document)
    (component,) = document["components"]
    assert "scope" not in component and artifact.scope_losses == 1
    values = dict(props(component["properties"]))
    assert values["occurrence"]["scopes"] == [scope]
    assert values["projection-losses"] == ["cyclonedx-default-required-scope-unassessed"]


def retained_case():
    from sourcebastion.inventory.contract import canonical_bytes

    value = inventory(occurrences=(occurrence(),))
    artifact = emit(value)
    return {
        "inventory": json.loads(canonical_bytes(value)),
        "document": json.loads(artifact.content),
        "inventory_sha256": artifact.inventory_sha256,
        "bom_sha256": artifact.sha256,
        "identity_sha256": artifact.identity_sha256,
        "omitted_occurrences": artifact.omitted_occurrences,
        "omitted_relationships": artifact.omitted_relationships,
        "scope_losses": artifact.scope_losses,
    }


def host_binding_gate(case):
    path = Path(__file__).resolve().parents[1] / "scripts/validate-inventory-cyclonedx.py"
    spec = importlib.util.spec_from_file_location("trusted_cyclonedx_test_gate", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.check_binding(case, SCHEMAS)


def test_host_gate_binds_untampered_canonical_facts():
    host_binding_gate(retained_case())


@pytest.mark.parametrize("changed", [None, "typing-extensions", "jsonschema"])
def test_host_validator_refuses_changed_direct_or_transitive_tool_version(monkeypatch, changed):
    path = Path(__file__).resolve().parents[1] / "scripts/validate-inventory-cyclonedx.py"
    spec = importlib.util.spec_from_file_location("trusted_cyclonedx_version_gate", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    versions = dict(module.VALIDATOR_VERSIONS)
    assert versions["typing-extensions"] == "4.16.0" and len(versions) == 6
    if changed is not None:
        versions[changed] = "0.0.0"
    monkeypatch.setattr(module.importlib.metadata, "version", versions.__getitem__)
    if changed is None:
        assert module.validator_versions() == versions
    else:
        with pytest.raises(RuntimeError, match="unreviewed-cyclonedx-validator-version"):
            module.validator_versions()


@pytest.mark.parametrize(
    "tamper", ["source", "occurrence", "line", "context", "identity", "coverage", "stages", "scope-loss", "loss-count"]
)
def test_rehashing_schema_valid_bom_cannot_change_retained_canonical_facts(tamper):
    case = retained_case()
    document = case["document"]
    component = document["components"][0]

    def change_property(rows, suffix, field, value):
        (row,) = [row for row in rows if row["name"] == PREFIX + suffix]
        data = json.loads(row["value"])
        data[field] = value
        row["value"] = json.dumps(data, sort_keys=True, separators=(",", ":"))

    if tamper == "source":
        change_property(document["metadata"]["properties"], "export", "source_sha256", "0" * 64)
    elif tamper == "occurrence":
        change_property(component["properties"], "occurrence", "selected_version", "0.0.0")
    elif tamper in {"line", "context"}:
        field, value = ("line", 999) if tamper == "line" else ("additionalContext", "line:999")
        component["evidence"]["occurrences"][0][field] = value
    elif tamper == "identity":
        case["identity_sha256"] = "0" * 64
    elif tamper == "coverage":
        change_property(document["metadata"]["properties"], "coverage", "graph", "complete")
    elif tamper == "stages":
        change_property(document["metadata"]["properties"], "stages", "matching", "succeeded")
    elif tamper == "scope-loss":
        component["properties"] = [
            row for row in component["properties"] if row["name"] != PREFIX + "projection-losses"
        ]
    else:
        case["scope_losses"] = 0
    case["bom_sha256"] = hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()
    with pytest.raises(AssertionError):
        host_binding_gate(case)
