"""Source evidence, analysis ownership and refusal contracts for pip composition."""

import hashlib
from pathlib import Path

import pytest

from sourcebastion.inventory.compose_requirements import compose_requirements
from sourcebastion.inventory.contract import Environment, InventoryLimits, Producer, canonical_bytes
from sourcebastion.inventory.inputs import Source
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256

SHA = "a" * 64


def run(root, *, config=None, environment=None, limits=None):
    config = config or DiscoveryConfig()
    producer = Producer(
        name="test-controller",
        version="1",
        code_sha256=SHA,
        registry_sha256=REGISTRY_SHA256,
        config_sha256=config.sha256,
    )
    with Source(root) as source:
        return compose_requirements(
            source, source_sha256=SHA, producer=producer, environment=environment, config=config, limits=limits
        )


def files(root, values):
    for path, value in values.items():
        p = root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(value)


def test_flat_source_pins_have_analysis_ownership_and_no_invented_roots_or_edges(tmp_path):
    files(tmp_path, {"requirements.txt": "Pip==v26.0.1\n"})
    result = run(tmp_path)
    assert result.stages.inventory == "complete"
    assert result.roots == result.relationships == result.applications == ()
    (row,) = result.occurrences
    assert row.name == "pip" and row.selected_version == "26.0.1"
    assert row.declared_range == "==v26.0.1" and row.evidence_kind == "declared"
    assert row.root_id is row.installed_environment_id is None and row.directness == "unknown"
    assert row.analysis_scope_id == result.analysis_scopes[0].id and row.activation == "active"
    assert result.coverage.graph == result.coverage.environment == "unknown"
    assert row.selection_declaration_ids == (result.declarations[0].id,)
    assert result.coverage.inputs[0].source_sha256 == hashlib.sha256(b"Pip==v26.0.1\n").hexdigest()


def test_constraint_pin_selects_only_an_actual_requirement_and_retains_both_locators(tmp_path):
    files(
        tmp_path,
        {
            "requirements.txt": "-r .hidden/custom.config\n-c constraints.in\n",
            ".hidden/custom.config": "requests>=2,<3\n",
            "constraints.in": "requests==2.32.3\nunused==99\n",
        },
    )
    result = run(tmp_path)
    assert result.stages.inventory == "complete"
    (row,) = result.occurrences
    assert row.name == "requests" and row.selected_version == "2.32.3" and row.source.path == ".hidden/custom.config"
    evidence = {d.id: d for d in result.declarations}
    assert {evidence[key].source.path for key in row.selection_declaration_ids} == {
        ".hidden/custom.config",
        "constraints.in",
    }
    assert {d.kind for d in evidence.values()} == {"requirement", "constraint"}
    assert "unused" in {d.name for d in evidence.values()} and "unused" not in {p.name for p in result.occurrences}
    assert {r.kind for r in result.input_references} == {"include", "constraint"}
    assert not result.relationships and not result.roots


def test_shared_include_retains_distinct_origins_and_constraint_selections(tmp_path):
    files(
        tmp_path,
        {
            "a/requirements.txt": "-r ../shared.in\n-c selected.in\n",
            "a/selected.in": "pip==26.0.1\n",
            "b/requirements.txt": "-r ../shared.in\n-c selected.in\n",
            "b/selected.in": "pip==26.2\n",
            "shared.in": "pip>=26\n",
        },
    )
    result = run(tmp_path)
    # Custom selected.in files are also independent requirement origins unless
    # they are referenced; the references establish their constraint role here.
    assert result.stages.inventory == "complete"
    assert {p.selected_version for p in result.occurrences} == {"26.0.1", "26.2"}
    assert len(result.occurrences) == 2 and len(result.analysis_scopes) == 2
    assert len({p.id for p in result.occurrences}) == 2 and not result.roots
    covered = {r.source_path: r for r in result.coverage.inputs}
    assert len(covered["shared.in"].analysis_scope_ids) == 2


def test_constraint_only_input_is_not_a_package_inventory(tmp_path):
    files(tmp_path, {"constraints.txt": "pip==26.0.1\n"})
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and not result.occurrences
    assert len(result.declarations) == 1 and result.declarations[0].kind == "constraint"
    assert result.coverage.inputs[0].reason == "no-required-dependency-declaration"


def test_range_does_not_acquire_a_version_from_host_or_registry(tmp_path):
    files(tmp_path, {"requirements.txt": "pip>=26,<27\n"})
    result = run(tmp_path)
    (row,) = result.occurrences
    assert row.selected_version is None and row.purl == "pkg:pypi/pip"
    assert not row.selection_declaration_ids and result.stages.inventory == "partial"
    assert result.coverage.version_resolution == "partial"


@pytest.mark.parametrize(
    "required,constraint,reason",
    [
        ("pip==26.0.1\n", "pip>=27\n", "constraint-conflict"),
        ("pip==26.0.1\npip>=27\n", "", "conflicting-root-declarations"),
        ("pip==26.0.1\n", 'pip>=27; sys_platform == "linux"\n', "conditional-constraint-unresolved"),
        ("pip==26.0.1\n", "pip[socks]==26.0.1\n", "invalid-constraint-extras"),
    ],
)
def test_conflicting_or_unproved_contexts_cannot_admit_selected_versions(tmp_path, required, constraint, reason):
    files(tmp_path, {"requirements.txt": required + "-c constraints.txt\n", "constraints.txt": constraint})
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and reason in result.coverage.refusal_codes
    assert result.occurrences and all(p.selected_version is None for p in result.occurrences)
    assert not any(p.selection_declaration_ids for p in result.occurrences)


def test_disjoint_markers_keep_both_pins_unknown_without_a_target(tmp_path):
    files(tmp_path, {"requirements.txt": 'pip==26.0.1; python_version < "3.13"\npip==26.2; python_version >= "3.13"\n'})
    result = run(tmp_path)
    assert result.stages.inventory == "complete" and len(result.occurrences) == 2
    assert {p.selected_version for p in result.occurrences} == {"26.0.1", "26.2"}
    assert {p.activation for p in result.occurrences} == {"unknown"}
    target = run(tmp_path, environment=Environment(policy="explicit-target", python_version="3.12.9"))
    assert {p.selected_version: p.activation for p in target.occurrences} == {"26.0.1": "active", "26.2": "inactive"}
    assert result.environment_sha256 != target.environment_sha256


def test_overlapping_different_marker_pins_are_visible_unresolved(tmp_path):
    files(tmp_path, {"requirements.txt": 'pip==26.0.1; python_version >= "3.12"\npip==26.2; python_version < "3.14"\n'})
    result = run(tmp_path)
    assert "overlapping-marker-context-unresolved" in result.coverage.refusal_codes
    assert all(p.selected_version is None for p in result.occurrences)


def test_equivalent_conjunction_order_shares_selection_context(tmp_path):
    files(
        tmp_path,
        {
            "requirements.txt": 'pip>=26; python_version < "3.13" and sys_platform == "linux"\n'
            'pip==26.0.1; sys_platform == "linux" and python_version < "3.13"\n'
        },
    )
    result = run(tmp_path)
    assert result.stages.inventory == "complete" and {p.selected_version for p in result.occurrences} == {"26.0.1"}


@pytest.mark.parametrize(
    "parent", ["-r child.in\n--unknown-option\n", "-r missing.in\n-r child.in\n", "-r child.in\n-r requirements.txt\n"]
)
def test_refused_parent_or_cycle_never_promotes_an_included_child(tmp_path, parent):
    files(tmp_path, {"requirements.txt": parent, "child.in": "pip==26.0.1\n"})
    result = run(tmp_path)
    assert result.stages.inventory == "partial"
    assert not any(p.selected_version for p in result.occurrences)


def test_ignored_constraint_cannot_authorize_unchecked_selection(tmp_path):
    files(
        tmp_path,
        {"requirements.txt": "pip==26.0.1\n-c hidden/constraints.txt\n", "hidden/constraints.txt": "pip>=27\n"},
    )
    result = run(tmp_path, config=DiscoveryConfig(ignored=("hidden",)))
    assert result.stages.inventory == "partial" and "ignored-required-reference" in result.coverage.refusal_codes
    assert all(p.selected_version is None for p in result.occurrences)
    (reference,) = result.input_references
    assert reference.disposition == "ignored" and reference.target_sha256 is None


def test_cycle_component_owns_lexicographically_earlier_descendant(tmp_path):
    files(
        tmp_path,
        {
            "z.in": "-r y.in\n-r a.in\n",
            "y.in": "-r z.in\n",
            "a.in": "pip==26.0.1\n",
            "independent.in": "setuptools==80.0\n",
        },
    )
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and "include-cycle" in result.coverage.refusal_codes
    assert {p.name for p in result.occurrences if p.selected_version is not None} == {"setuptools"}
    assert len(result.analysis_scopes) == 2


def test_custom_hash_lock_keeps_artifact_hash_without_installed_claim(tmp_path):
    text = "pip==26.0.1 --hash=sha256:" + SHA + "\n"
    files(tmp_path, {".github/python-locks/runtime.txt": text})
    result = run(tmp_path)
    (row,) = result.occurrences
    assert row.hashes[0].digest == SHA and row.hashes[0].kind == "artifact"
    assert row.evidence_kind == "declared" and row.installed_environment_id is None


def test_bare_custom_name_requires_explicit_mapping_and_unrelated_prose_is_not_a_package(tmp_path):
    files(tmp_path, {"custom.in": "pip\n", "README.txt": "Welcome to the project.\n"})
    assert not run(tmp_path).occurrences
    mapped = run(tmp_path, config=DiscoveryConfig(mappings=(("custom.in", "pip-requirements"),)))
    (row,) = mapped.occurrences
    assert row.name == "pip" and row.selected_version is None and mapped.stages.inventory == "partial"


def test_known_other_format_keeps_coverage_unsupported(tmp_path):
    files(tmp_path, {"requirements.txt": "pip==26.0.1\n", "package.json": '{"dependencies":{"a":"1.2.3"}}'})
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and result.occurrences[0].selected_version == "26.0.1"
    assert {r.source_path: r.disposition for r in result.coverage.inputs}["package.json"] == "unsupported"


def test_final_epoch_failure_discards_all_consumable_records(tmp_path, monkeypatch):
    files(tmp_path, {"requirements.txt": "pip==26.0.1\n"})
    original, calls = Source.validate, 0

    def changed(source):
        nonlocal calls
        calls += 1
        if calls == 2:
            (tmp_path / "requirements.txt").write_text("pip==26.2\n")
        return original(source)

    monkeypatch.setattr(Source, "validate", changed)
    result = run(tmp_path)
    assert calls == 2 and result.stages.inventory == "failed"
    assert result.occurrences == result.declarations == result.input_references == result.analysis_scopes == ()
    assert any(code.startswith("changed-") for code in result.coverage.refusal_codes)


def test_controller_identity_and_recorded_source_limits_cannot_mismatch(tmp_path):
    files(tmp_path, {"requirements.txt": "pip==26.0.1\n"})
    with pytest.raises(ValueError, match="limit-mismatch"):
        run(tmp_path, limits=InventoryLimits(source_file_bytes=1))
    with Source(tmp_path) as source:
        producer = Producer(name="test", version="1", code_sha256=SHA, registry_sha256=SHA, config_sha256=SHA)
        with pytest.raises(ValueError, match="producer-discovery"):
            compose_requirements(source, source_sha256=SHA, producer=producer)


def test_shared_semantic_and_occurrence_budget_refusals_do_not_publish_truncated_success(tmp_path):
    files(tmp_path, {"requirements.txt": "pip==26.0.1\nsetuptools==80.0\n"})
    for kwargs in (dict(config=DiscoveryConfig(semantic_checks=1)), dict(limits=InventoryLimits(occurrences=1))):
        result = run(tmp_path, **kwargs)
        assert result.stages.inventory == "failed" and not result.occurrences
        assert any("budget" in code for code in result.coverage.refusal_codes)


def test_duplicate_declarations_share_selection_work_and_bounded_evidence(tmp_path):
    files(
        tmp_path,
        {"requirements.txt": "pip>=26\n" * 500 + "-c constraints.txt\n", "constraints.txt": "pip==26.0.1\n" * 500},
    )
    result = run(tmp_path)
    assert result.stages.inventory == "complete" and len(result.occurrences) == 500 and len(result.declarations) == 1000
    assert max(len(row.selection_declaration_ids) for row in result.occurrences) <= 3


def test_canonical_output_repeats_exactly_and_preserves_source_bytes(tmp_path):
    files(tmp_path, {"requirements.txt": "pip>=26\n-c constraints.txt\n", "constraints.txt": "pip==26.0.1\n"})
    before = {p.relative_to(tmp_path).as_posix(): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert canonical_bytes(run(tmp_path)) == canonical_bytes(run(tmp_path))
    assert before == {p.relative_to(tmp_path).as_posix(): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}


def test_unrepresentable_source_paths_fail_without_inventing_locations(tmp_path):
    files(tmp_path, {"requirements.txt": "pip==26.0.1\n", "bad\rname.in": "pip==26.2\n"})
    result = run(tmp_path)
    assert result.stages.inventory == "failed" and not result.occurrences
    assert "unrepresentable-input-coverage" in result.coverage.refusal_codes


def test_actual_discovery_visits_not_deduplicated_references_consume_shared_budget(tmp_path):
    from sourcebastion.inventory.discovery import discover

    files(
        tmp_path,
        {
            "requirements.txt": "pip>=26\n-r shared.in\n-c shared.in\n",
            "shared.in": "-c constraints.in\n",
            "constraints.in": "pip==26.0.1\n",
        },
    )
    with Source(tmp_path) as source:
        found = discover(source)
    assert found.semantic_checks == 5 and len(found.references) == 4
    # Prior implementation admitted complete at73 by losing one deduplicated
    # visit. All actual discovery/composition work must fit the same ceiling.
    result = run(tmp_path, config=DiscoveryConfig(semantic_checks=73))
    assert result.stages.inventory == "failed"
    assert result.occurrences == result.declarations == result.input_references == ()
    assert "composition-check-budget-exceeded" in result.coverage.refusal_codes


def test_duplicate_requirement_evidence_expansion_and_validation_share_budget(tmp_path, monkeypatch):
    from packaging.specifiers import SpecifierSet

    files(
        tmp_path,
        {
            "requirements.txt": "pip>=0\n" * 50 + "-c constraints.in\n",
            "constraints.in": "pip==1\n" + "".join("pip>=0." + str(n) + "\n" for n in range(1, 100)),
        },
    )
    original, calls = SpecifierSet.contains, 0

    def counted(selector, *args, **kwargs):
        nonlocal calls
        calls += 1
        return original(selector, *args, **kwargs)

    monkeypatch.setattr(SpecifierSet, "contains", counted)
    result = run(tmp_path, config=DiscoveryConfig(semantic_checks=1131))
    assert result.stages.inventory == "failed"
    assert result.occurrences == result.declarations == result.input_references == ()
    assert "composition-check-budget-exceeded" in result.coverage.refusal_codes
    assert calls <= 1131


def test_selection_links_and_full_typed_structure_refuse_before_large_validation(tmp_path):
    files(
        tmp_path,
        {
            "requirements.txt": "pip>=0\n" * 50 + "-c constraints.in\n",
            "constraints.in": "pip==1\n" + "".join("pip>=0." + str(n) + "\n" for n in range(1, 100)),
        },
    )
    result = run(tmp_path, limits=InventoryLimits(export_nodes=1000))
    assert result.stages.inventory == "failed"
    assert result.occurrences == result.declarations == result.input_references == ()
    assert "composition-structure-budget-exceeded" in result.coverage.refusal_codes
    files(tmp_path, {"requirements.txt": "pip==1\n"})
    result = run(tmp_path, limits=InventoryLimits(export_nodes=50))
    assert result.stages.inventory == "failed" and not result.occurrences
    assert "composition-structure-budget-exceeded" in result.coverage.refusal_codes
