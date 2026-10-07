"""Canonical authority and loss invariants before any production adapter joins."""

import base64
import json
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from sourcebastion.inventory.contract import (
    AnalysisScope,
    Application,
    ContentHash,
    Coverage,
    Environment,
    InputCoverage,
    Inventory,
    InventoryLimits,
    Locator,
    Occurrence,
    Producer,
    ProjectionLoss,
    Relationship,
    Root,
    StageStates,
    canonical_bytes,
    identifier,
    go_module_hash,
    package_purl,
)

SHA = "a" * 64


def locator(path="requirements.txt"):
    return Locator(path=path, source_sha256=SHA, locator="line:1", parser="pip-requirements/1")


def occurrence(path="requirements.txt", **changes):
    values = dict(
        id=identifier(
            "occurrence",
            [
                path,
                {
                    key: value.model_dump(mode="json") if isinstance(value, BaseModel) else value
                    for key, value in changes.items()
                },
            ],
        ),
        source=locator(path),
        ecosystem="pypi",
        name="pip",
        purl="pkg:pypi/pip@26.0.1",
        evidence_kind="declared",
        selected_version="26.0.1",
    )
    values.update(changes)
    return Occurrence(**values)


def inventory(**changes):
    environment = changes.pop("environment", Environment())
    paths = {"requirements.txt": SHA}
    for key in (
        "roots",
        "analysis_scopes",
        "installed_environments",
        "occurrences",
        "relationships",
        "applications",
        "losses",
    ):
        for row in changes.get(key, ()):
            paths[row.source.path] = row.source.source_sha256
    coverage = Coverage(
        discovery="complete",
        enumeration="complete",
        version_resolution="complete",
        graph="unknown",
        environment="unknown",
        inputs=tuple(
            InputCoverage(
                source_path=path,
                source_sha256=digest,
                format="pip-requirements",
                parser="pip-requirements/1",
                disposition="parsed",
                reason="static-input",
            )
            for path, digest in sorted(paths.items())
        ),
    )
    values = dict(
        source_sha256=SHA,
        producer=Producer(name="test-controller", version="1", code_sha256=SHA, registry_sha256=SHA, config_sha256=SHA),
        environment=environment,
        environment_sha256=environment.sha256,
        coverage=coverage,
        stages=StageStates(inventory="complete"),
    )
    values.update(changes)
    return Inventory(**values)


def test_json_roundtrip_publishes_strict_independent_contract_versions():
    record = inventory(occurrences=(occurrence(),))
    encoded = canonical_bytes(record)
    assert Inventory.model_validate_json(encoded) == record
    data = json.loads(encoded)
    assert data["schema_version"] == "sourcebastion.inventory/1"
    assert data["coverage"]["schema_version"] == "sourcebastion.inventory-coverage/1"
    assert data["environment"]["schema_version"] == "sourcebastion.environment/1"
    assert data["limits"]["schema_version"] == "sourcebastion.inventory-limits/1"
    assert Inventory.model_json_schema()["additionalProperties"] is False


@pytest.mark.parametrize(
    "changes",
    [dict(unknown=True), dict(source_sha256="BAD"), dict(source_sha256=True), dict(environment_sha256="b" * 64)],
)
def test_unknown_fields_and_unbound_identity_are_rejected(changes):
    with pytest.raises(ValidationError):
        inventory(**changes)


@pytest.mark.parametrize("path", ["../requirements.txt", "/etc/passwd", "a/../b.txt", "a//b.txt", "a\\b.txt", "."])
def test_source_paths_are_canonical_and_confined(path):
    with pytest.raises(ValueError):
        locator(path)


def test_equal_purls_keep_separate_source_roots_and_occurrence_ids():
    roots = tuple(
        Root(id=identifier("root", path), path=path, source=locator(path + "/requirements.txt")) for path in ("a", "b")
    )
    rows = tuple(occurrence(root.path + "/requirements.txt", root_id=root.id) for root in roots)
    data = inventory(roots=roots, occurrences=rows)
    assert rows[0].purl == rows[1].purl and rows[0].id != rows[1].id
    assert len(json.loads(canonical_bytes(data))["occurrences"]) == 2


def test_unknown_ownership_is_separate_from_analysis_scope():
    scope = AnalysisScope(id=identifier("scope", "requirements-origin"), kind="requirements-origin", source=locator())
    row = occurrence(analysis_scope_id=scope.id)
    record = inventory(analysis_scopes=(scope,), occurrences=(row,))
    assert record.occurrences[0].root_id is None
    with pytest.raises(ValidationError, match="unbound-occurrence-context"):
        inventory(analysis_scopes=(scope,), occurrences=(occurrence(root_id=scope.id),))


def test_installed_evidence_does_not_borrow_source_project_ownership():
    with pytest.raises(ValidationError, match="cannot-borrow-source-root"):
        occurrence(evidence_kind="installed", root_id=identifier("root", "."))
    with pytest.raises(ValidationError, match="not-installed"):
        occurrence(installed_environment_id=identifier("environment", "host"))
    assert occurrence(evidence_kind="installed").root_id is None


@pytest.mark.parametrize(
    "changes",
    [
        dict(purl="pkg:pypi/pip@26.2"),
        dict(ecosystem="npm"),
        dict(name="https://user:secret@example.invalid/pip"),
        dict(selected_version="https://example.invalid/x"),
    ],
)
def test_contradictory_identity_is_refused(changes):
    with pytest.raises(ValidationError):
        occurrence(**changes)


def test_range_retains_no_guessed_selected_version():
    row = occurrence(purl="pkg:pypi/pip", selected_version=None, declared_range=">=26,<27")
    coverage = inventory().coverage.model_copy(update={"version_resolution": "partial"})
    record = inventory(occurrences=(row,), coverage=coverage, stages=StageStates(inventory="partial"))
    assert record.occurrences[0].selected_version is None
    assert record.occurrences[0].declared_range == ">=26,<27"
    with pytest.raises(ValidationError, match="cannot-be-promoted"):
        inventory(occurrences=(row,), coverage=coverage)


def test_conditional_and_unassessed_relationships_remain_distinct():
    parent, child = occurrence("a.txt"), occurrence("b.txt")
    edge = Relationship(
        id=identifier("relationship", "edge"),
        parent_id=parent.id,
        child_id=child.id,
        source=locator("a.txt"),
        evidence_status="evidenced",
        marker='python_version < "3.12"',
        extras=("socks",),
        activation="unknown",
    )
    loss = ProjectionLoss(
        id=identifier("loss", "conditional-edge"),
        source=edge.source,
        dimension="graph",
        reason="conditional-relationship-not-standard-exportable",
        relationship_id=edge.id,
    )
    record = inventory(occurrences=(parent, child), relationships=(edge,), losses=(loss,))
    assert record.relationships[0].activation == "unknown" and record.losses[0].relationship_id == edge.id
    # Unassessed contextual observations remain labelled; the matcher adapter
    # must filter by evidence_status and cannot reinterpret this as proof.
    assert edge.model_copy(update={"evidence_status": "unassessed"}).evidence_status == "unassessed"


def test_graph_endpoints_and_losses_must_bind_occurrences():
    row = occurrence()
    edge = Relationship(
        id=identifier("relationship", "missing"),
        parent_id=row.id,
        child_id=identifier("occurrence", "missing"),
        source=locator(),
        evidence_status="evidenced",
    )
    with pytest.raises(ValidationError, match="unbound-relationship"):
        inventory(occurrences=(row,), relationships=(edge,))
    loss = ProjectionLoss(
        id=identifier("loss", "missing"), source=locator(), dimension="graph", reason="missing", relationship_id=edge.id
    )
    with pytest.raises(ValidationError, match="unbound-projection-loss"):
        inventory(losses=(loss,))


def test_duplicate_or_mistyped_ids_and_coverage_paths_are_refused():
    row = occurrence()
    with pytest.raises(ValidationError, match="duplicate-or-mistyped"):
        inventory(occurrences=(row, row))
    with pytest.raises(ValidationError, match="duplicate-or-mistyped"):
        inventory(occurrences=(occurrence(id=identifier("root", "wrong")),))
    coverage = inventory().coverage
    with pytest.raises(ValidationError, match="duplicate-input-coverage"):
        inventory(coverage=coverage.model_copy(update={"inputs": coverage.inputs * 2}))


@pytest.mark.parametrize("disposition", ["unsupported", "failed", "bounded-omission", "unresolved", "discovered"])
def test_matching_success_never_upgrades_incomplete_coverage(disposition):
    coverage = inventory().coverage
    row = coverage.inputs[0].model_copy(update={"disposition": disposition})
    coverage = coverage.model_copy(update={"inputs": (row,), "enumeration": "partial"})
    with pytest.raises(ValidationError, match="cannot-be-promoted"):
        inventory(coverage=coverage, stages=StageStates(inventory="complete", export="succeeded", matching="succeeded"))
    record = inventory(
        coverage=coverage, stages=StageStates(inventory="partial", export="succeeded", matching="succeeded")
    )
    assert record.coverage.enumeration == "partial" and record.stages.inventory == "partial"


def test_stage_failures_preserve_admitted_inventory_and_require_dependencies():
    record = inventory(
        occurrences=(occurrence(),), stages=StageStates(inventory="complete", export="succeeded", matching="failed")
    )
    assert record.occurrences and record.stages.matching == "failed"
    with pytest.raises(ValidationError):
        StageStates(inventory="failed", export="succeeded")
    with pytest.raises(ValidationError):
        StageStates(inventory="partial", matching="succeeded")
    with pytest.raises(ValidationError, match="failed-inventory"):
        inventory(occurrences=(occurrence(),), stages=StageStates(inventory="failed"))


def test_environment_defaults_unknown_without_host_fallback():
    target = Environment()
    assert target.policy == "preserve-alternatives" and target.python_version is None
    with pytest.raises(ValidationError):
        Environment(python_version="3.14.8")
    explicit = Environment(policy="explicit-target", python_version="3.12.0")
    assert explicit.sha256 != target.sha256
    with pytest.raises(ValidationError):
        Environment(policy="explicit-target", marker_inputs=(("python_version", "3.12"), ("python_version", "3.14")))


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(cpu_quota=2.1),
        dict(charged_memory_bytes=2 * 1024**3 + 1),
        dict(swap_bytes=1),
        dict(aggregate_cpu_seconds=121.0),
        dict(pipeline_wall_seconds=151.0),
        dict(traversal_entries=100001),
        dict(occurrences=100001),
        dict(relationships=500001),
        dict(semantic_checks=5000001),
        dict(export_nodes=2000001),
        dict(inventory_bytes=64 * 1024**2 + 1),
        dict(pids=True),
        dict(swap_bytes=False),
    ],
)
def test_recorded_limits_cannot_raise_s01_ceilings(kwargs):
    with pytest.raises(ValidationError):
        InventoryLimits(**kwargs)


def test_serialization_is_deterministic_and_budget_refusal_is_not_truncation():
    a, b = occurrence("a.txt"), occurrence("b.txt")
    assert canonical_bytes(inventory(occurrences=(a, b))) == canonical_bytes(inventory(occurrences=(b, a)))
    with pytest.raises(ValueError, match="output-budget"):
        canonical_bytes(inventory(), max_bytes=1)
    with pytest.raises(ValueError, match="structure-budget"):
        canonical_bytes(inventory(), max_nodes=1)
    with pytest.raises(ValueError, match="output-budget"):
        canonical_bytes(inventory(limits=InventoryLimits(inventory_bytes=1)))
    with pytest.raises(ValidationError, match="record-budget"):
        inventory(limits=InventoryLimits(occurrences=1), occurrences=(a, b))


def test_hash_and_purl_types_retain_ecosystem_semantics():
    assert package_purl("npm", "@scope/package", "1.2.3") == "pkg:npm/%40scope/package@1.2.3"
    assert package_purl("golang", "github.com/org/module", "v1.2.3+incompatible").endswith("@v1.2.3%2Bincompatible")
    assert ContentHash(algorithm="go-h1", digest=SHA, kind="module-tree").digest == SHA
    with pytest.raises(ValidationError):
        ContentHash(algorithm="sha256", digest="b" * 63, kind="artifact")
    with pytest.raises(ValidationError):
        ContentHash(algorithm="go-h1", digest=SHA, kind="artifact")
    with pytest.raises(ValidationError):
        occurrence(extras=("socks\x00private",))


def test_serialization_revalidates_model_copy_and_nested_instance_bypasses():
    record = inventory()
    forged = record.model_copy(update={"source_sha256": "not-a-digest"})
    with pytest.raises(ValidationError):
        canonical_bytes(forged)
    forged_coverage = record.coverage.model_copy(update={"discovery": "invented-success"})
    with pytest.raises(ValidationError):
        inventory(coverage=forged_coverage)


def test_explicit_environment_retains_only_supplied_inputs_and_refuses_conflicts():
    target = Environment(policy="explicit-target", python_version="3.12.0", platform="linux", architecture="aarch64")
    assert target.marker_environment == {
        "python_version": "3.12",
        "python_full_version": "3.12.0",
        "sys_platform": "linux",
        "platform_machine": "aarch64",
    }
    assert "os_name" not in target.marker_environment
    assert Environment().marker_environment == {}
    assert Environment(policy="explicit-target", python_version="3.12").marker_environment == {"python_version": "3.12"}
    with pytest.raises(ValidationError, match="contradictory-environment"):
        Environment(policy="explicit-target", python_version="3.12.0", marker_inputs=(("python_version", "3.14"),))
    with pytest.raises(ValidationError, match="unknown-environment"):
        Environment(policy="explicit-target", marker_inputs=(("arbitrary", "host-fallback"),))


def test_published_structural_schema_tracks_the_implemented_contract():
    path = Path(__file__).resolve().parents[1] / "docs/M046-inventory-v1.schema.json"
    assert json.loads(path.read_text()) == Inventory.model_json_schema()


def test_environment_marker_order_does_not_change_identity_or_canonical_bytes():
    items = (("os_name", "posix"), ("platform_system", "Linux"))
    a = Environment(policy="explicit-target", marker_inputs=items)
    b = Environment(policy="explicit-target", marker_inputs=tuple(reversed(items)))
    assert a.sha256 == b.sha256
    assert canonical_bytes(inventory(environment=a)) == canonical_bytes(inventory(environment=b))


def test_unselected_versions_cannot_claim_complete_resolution():
    row = occurrence(selected_version=None, purl="pkg:pypi/pip", declared_range=">=26,<27")
    for stage in ("complete", "partial"):
        with pytest.raises(ValidationError, match="unresolved-version-cannot-be-complete"):
            inventory(occurrences=(row,), stages=StageStates(inventory=stage))
    with pytest.raises(ValidationError, match="cannot-be-promoted"):
        inventory(occurrences=(occurrence(purl=None),))


def test_global_refusal_cannot_coexist_with_complete_inventory():
    coverage = inventory().coverage.model_copy(update={"refusal_codes": ("input-deadline",)})
    with pytest.raises(ValidationError, match="cannot-be-promoted"):
        inventory(coverage=coverage)
    assert inventory(coverage=coverage, stages=StageStates(inventory="partial")).coverage.refusal_codes


@pytest.mark.parametrize("path,digest", [("uncovered.txt", SHA), ("requirements.txt", "b" * 64)])
def test_all_record_sources_require_hash_bound_input_coverage(path, digest):
    source = Locator(path=path, source_sha256=digest, locator="line:1", parser="test/1")
    base = inventory()
    records = (
        ("roots", Root(id=identifier("root", "."), path=".", source=source)),
        ("analysis_scopes", AnalysisScope(id=identifier("scope", "x"), kind="lock-input", source=source)),
        ("occurrences", occurrence(source=source)),
        ("losses", ProjectionLoss(id=identifier("loss", "x"), source=source, dimension="graph", reason="unknown")),
    )
    for field, row in records:
        with pytest.raises(ValidationError, match="unbound-source-coverage"):
            inventory(**{field: (row,), "coverage": base.coverage})


def test_input_coverage_contexts_bind_without_inventing_ownership():
    root = Root(id=identifier("root", "."), path=".", source=locator())
    scope = AnalysisScope(id=identifier("scope", "x"), kind="requirements-origin", source=locator())
    base = inventory(roots=(root,), analysis_scopes=(scope,))
    row = base.coverage.inputs[0].model_copy(update={"root_ids": (root.id,), "analysis_scope_ids": (scope.id,)})
    record = inventory(
        roots=(root,), analysis_scopes=(scope,), coverage=base.coverage.model_copy(update={"inputs": (row,)})
    )
    assert record.coverage.inputs[0].root_ids == (root.id,)
    assert base.coverage.inputs[0].root_ids == ()
    for ids in ((identifier("root", "missing"),), (root.id, root.id)):
        bad = row.model_copy(update={"root_ids": ids})
        with pytest.raises(ValidationError, match="coverage-context"):
            inventory(
                roots=(root,), analysis_scopes=(scope,), coverage=base.coverage.model_copy(update={"inputs": (bad,)})
            )


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(python_version="3.12", marker_inputs=(("python_full_version", "3.14.8"),)),
        dict(marker_inputs=(("python_version", "3.12"), ("python_full_version", "3.14.8"))),
        dict(marker_inputs=(("python_full_version", "3.12"),)),
        dict(marker_inputs=(("python_version", "3.12.0"),)),
    ],
)
def test_python_target_version_families_are_consistent(kwargs):
    with pytest.raises(ValidationError):
        Environment(policy="explicit-target", **kwargs)
    assert Environment(
        policy="explicit-target", python_version="3.12", marker_inputs=(("python_full_version", "3.12.9"),)
    )


def test_actual_go_sum_encoding_roundtrips_to_typed_decoded_tree_hash():
    raw = "h1:" + base64.b64encode(bytes.fromhex(SHA)).decode("ascii")
    parsed = go_module_hash(raw)
    assert parsed.algorithm == "go-h1" and parsed.kind == "module-tree" and parsed.digest == SHA
    assert "h1:" + base64.b64encode(bytes.fromhex(parsed.digest)).decode("ascii") == raw
    for invalid in ("h1:" + SHA, raw[:-1], raw.replace("=", "!"), "sha256:" + raw[3:], "h1:" + "a" * 44):
        with pytest.raises(ValueError, match="invalid-go-module-hash"):
            go_module_hash(invalid)


@pytest.mark.parametrize(
    "ecosystem,name,version",
    [
        ("pypi", "Pip", "26.0.1"),
        ("pypi", "my_package", "1.0"),
        ("pypi", "pip", "latest"),
        ("pypi", "pip", "v1.0"),
        ("maven", "artifact", "1.0"),
        ("composer", "package", "1.0"),
        ("npm", "@scope", "1.0"),
        ("npm", "@/package", "1.0"),
        ("npm", "a/b", "1.0"),
        ("npm", "package", "latest"),
        ("npm", "package", "1.02.3"),
        ("npm", "package", "1.2.3-01"),
        ("cargo", "package", "main"),
        ("golang", "example.com/module", "1.2.3"),
        ("nuget", "Package", "1.0"),
        ("composer", "Vendor/package", "1.0"),
    ],
)
def test_canonical_identity_rejects_unresolved_versions_and_missing_namespaces(ecosystem, name, version):
    with pytest.raises(ValueError):
        package_purl(ecosystem, name, version)


def test_lowered_structure_budget_refuses_before_graph_revalidation_or_dump(monkeypatch):
    record = inventory(occurrences=tuple(occurrence(str(n) + ".txt") for n in range(100)))

    def forbidden(*_args, **_kwargs):
        pytest.fail("graph copied before structure budget refusal")

    monkeypatch.setattr(Inventory, "model_validate", forbidden)
    monkeypatch.setattr(Inventory, "model_dump", forbidden)
    with pytest.raises(ValueError, match="structure-budget"):
        canonical_bytes(record, max_nodes=128)


def test_serialization_revalidates_limits_before_using_effective_caps():
    forged = inventory().model_copy(update={"limits": InventoryLimits.model_construct(export_nodes=2000001)})
    with pytest.raises(ValidationError):
        canonical_bytes(forged)
