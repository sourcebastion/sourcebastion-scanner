"""Lock graph provenance, unresolved selectors and shared bounded admission."""

import hashlib
import json
from pathlib import Path
import pytest
from pydantic import ValidationError
from sourcebastion.inventory.compose_source import compose_source
from sourcebastion.inventory.contract import Environment, Inventory, InventoryLimits, Producer, canonical_bytes
from sourcebastion.inventory.inputs import Source, InputRefusal
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256
from sourcebastion.inventory.python_locks import parse

SHA = "a" * 64

POETRY = '[metadata]\nlock-version="2.1"\npython-versions=">=3.12"\ncontent-hash="' + SHA + '"\n'

PDM = (
    '[metadata]\nlock_version="4.5.0"\ngroups=["default","test"]\nstrategy=["inherit_metadata"]\ncontent_hash="sha256:'
    + SHA
    + '"\n'
)

UV = 'version=1\nrevision=3\nrequires-python=">=3.12"\n'

SOURCE = 'source={registry="https://pypi.org/simple"}\n'


def artifact(name, version="1", style="poetry"):
    if style == "uv":
        return (
            'wheels=[{url="https://packages.invalid/'
            + name
            + "-"
            + version
            + '-py3-none-any.whl",hash="sha256:'
            + SHA
            + '"}]\n'
        )
    return 'files=[{file="' + name + "-" + version + '-py3-none-any.whl",hash="sha256:' + SHA + '"}]\n'


def package(name="foo", version="1", style="poetry", extra=""):
    header = '[[package]]\nname="' + name + '"\nversion="' + version + '"\n'
    fields = {
        "poetry": 'optional=false\npython-versions=">=3.12"\ngroups=["main"]\n',
        "pdm": 'requires_python=">=3.12"\ngroups=["default"]\n',
        "uv": SOURCE,
    }
    return header + fields[style] + artifact(name, version, style) + extra


def run(root, content, style, *, environment=None, config=None, limits=None, unchanged=True):
    name = {
        "poetry": "poetry.lock",
        "pdm": "pdm.lock",
        "uv": "uv.lock",
        "pylock": "pylock.toml",
        "pipfile": "Pipfile.lock",
    }[style]
    (root / name).write_text(content)
    before = {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()}
    config = config or DiscoveryConfig()
    with Source(root) as source:
        inventory = compose_source(
            source,
            source_sha256=SHA,
            producer=Producer(
                name="test", version="1", code_sha256=SHA, registry_sha256=REGISTRY_SHA256, config_sha256=config.sha256
            ),
            environment=environment,
            config=config,
            limits=limits,
        )
    if unchanged:
        assert before == {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()}
    encoded = canonical_bytes(inventory)
    assert canonical_bytes(Inventory.model_validate_json(encoded)) == encoded
    return inventory


@pytest.mark.parametrize("style,header", [("poetry", POETRY), ("pdm", PDM), ("uv", UV)])
def test_lock_pin_retains_hash_scope_source_without_project_or_installation(tmp_path, style, header):
    result = run(tmp_path, header + package(style=style), style)
    assert result.stages.inventory == "complete"
    (row,) = result.occurrences
    assert row.evidence_kind == "locked" and row.selected_version == "1" and row.purl == "pkg:pypi/foo@1"
    assert row.activation == row.directness == "unknown" and row.root_id is row.installed_environment_id is None
    assert not result.roots and not result.applications and not result.installed_environments
    assert row.hashes[0].digest == SHA and row.hashes[0].kind == "artifact"
    assert row.registry_source_sha256 == (
        hashlib.sha256(b"https://pypi.org/simple").hexdigest() if style == "uv" else None
    )
    assert result.analysis_scopes[0].kind == "lock-input"
    assert result.coverage.environment == result.coverage.graph == "unknown"
    assert result.stages.export == result.stages.matching == "not-run"


def test_lock_does_not_borrow_nearby_project_root_or_requirement_pin(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="app"\nversion="1"\ndependencies=["foo>=2"]\n')
    result = run(tmp_path, UV + package(style="uv"), "uv")
    assert len(result.roots) == 1 and len(result.occurrences) == 2
    declared = next(p for p in result.occurrences if p.evidence_kind == "declared")
    locked = next(p for p in result.occurrences if p.evidence_kind == "locked")
    assert declared.selected_version is None and declared.root_id == result.roots[0].id
    assert locked.root_id is None and locked.selected_version == "1" and not result.relationships


def test_poetry_groups_optional_markers_and_requires_python_remain_separate(tmp_path):
    text = (
        package(extra="markers={Main=\"os_name == 'posix'\"}\n")
        .replace('groups=["main"]', 'groups=["Main","test"]')
        .replace("optional=false", "optional=true")
    )
    result = run(tmp_path, POETRY + text, "poetry")
    assert len(result.occurrences) == 2
    rows = {p.groups: p for p in result.occurrences}
    assert rows[("main",)].marker == 'os_name == "posix"' and rows[("test",)].marker is None
    assert all(p.lock_optional is True and p.activation == "unknown" for p in rows.values())
    assert {a.kind for a in result.applicability} == {"group", "python-version"}


@pytest.mark.parametrize(
    "style,header,dependency",
    [("poetry", POETRY, '[package.dependencies]\nfoo=">=1,<2"\n'), ("pdm", PDM, 'dependencies=["foo>=1,<2"]\n')],
)
def test_multigroup_edges_bind_same_source_group_and_retain_selector(tmp_path, style, header, dependency):
    default = "main" if style == "poetry" else "default"
    parent = package("parent", style=style, extra=dependency).replace(
        f'groups=["{default}"]', f'groups=["{default}","test"]'
    )
    child = package(style=style).replace(f'groups=["{default}"]', f'groups=["{default}","test"]')
    result = run(tmp_path, header + parent + child, style)
    assert result.stages.inventory == "complete" and len(result.occurrences) == 4
    assert len(result.relationships) == len(result.dependency_selectors) == 2
    rows = {p.id: p for p in result.occurrences}
    selectors = {s.id: s for s in result.dependency_selectors}
    for edge in result.relationships:
        selector = selectors[edge.selector_id]
        assert rows[edge.parent_id].groups == rows[edge.child_id].groups == selector.groups
        assert selector.declared_range in {">=1,<2", "<2,>=1"}
        assert selector.dialect == ("poetry-core-2.1.3" if style == "poetry" else "pep440")
        assert (
            selector.disposition == "resolved" and edge.evidence_status == "evidenced" and edge.activation == "unknown"
        )
    assert result.coverage.graph == "partial"


def test_poetry_caret_uses_maintained_dialect_and_selects_exact_source_version(tmp_path):
    text = (
        POETRY
        + package("parent", extra='[package.dependencies]\nfoo="^2.0"\n')
        + package("foo", "1", extra="markers=\"python_version < '3.14'\"\n")
        + package("foo", "2", extra="markers=\"python_version >= '3.14'\"\n")
    )
    result = run(tmp_path, text, "poetry")
    assert result.stages.inventory == "complete" and len(result.relationships) == 1
    assert result.dependency_selectors[0].declared_range == "^2.0"
    child = next(p for p in result.occurrences if p.id == result.relationships[0].child_id)
    assert child.selected_version == "2" and child.marker == 'python_version >= "3.14"'


@pytest.mark.parametrize("selector", ['name="foo"', 'name="foo",version="1"'])
def test_uv_omitted_registry_is_not_repaired_from_filtered_candidates(tmp_path, selector):
    parent = package("parent", style="uv", extra="dependencies=[{" + selector + "}]\n")
    result = run(
        tmp_path, UV + parent + package(style="uv") + package(style="uv").replace("pypi.org", "other.invalid"), "uv"
    )
    assert result.stages.inventory == "partial" and not result.relationships
    (record,) = result.dependency_selectors
    assert record.child_id is None and record.name == "foo" and record.reason == "ambiguous-lock-dependency"
    assert record.source.locator == "package[0].dependencies[0]"
    assert record.marker_semantics == "relative-to-lock-python"
    assert "other.invalid" not in canonical_bytes(result).decode()


def test_uv_explicit_registry_keeps_equal_purls_and_source_selected_edge(tmp_path):
    parent = package(
        "parent",
        style="uv",
        extra='dependencies=[{name="foo",version="1",source={registry="https://other.invalid/simple"}}]\n',
    )
    result = run(
        tmp_path,
        UV
        + parent
        + package(style="uv")
        + package(style="uv").replace("https://pypi.org/simple", "https://other.invalid/simple"),
        "uv",
    )
    assert result.stages.inventory == "partial" and len(result.relationships) == 1
    rows = {p.id: p for p in result.occurrences}
    child = rows[result.relationships[0].child_id]
    assert child.registry_source_sha256 == hashlib.sha256(b"https://other.invalid/simple").hexdigest()
    assert result.dependency_selectors[0].registry_source_sha256 == child.registry_source_sha256
    assert len([p for p in rows.values() if p.purl == "pkg:pypi/foo@1"]) == 2
    assert "overlapping-lock-variants" in result.coverage.refusal_codes


@pytest.mark.parametrize("version,accepted", [("1+local", False), ("1.0", True), ("2", False)])
def test_uv_exact_selector_is_not_a_public_version_range(tmp_path, version, accepted):
    parent = package(
        "parent",
        style="uv",
        extra='dependencies=[{name="foo",version="1",source={registry="https://pypi.org/simple"}}]\n',
    )
    result = run(tmp_path, UV + parent + package("foo", version, style="uv"), "uv")
    assert bool(result.relationships) is accepted
    assert result.dependency_selectors[0].exact_version == "1"


def test_uv_relative_markers_never_borrow_explicit_target_inputs(tmp_path):
    parent = package(
        "parent", style="uv", extra='dependencies=[{name="foo",marker="python_version < \'3.14\'",extra=["test"]}]\n'
    )
    result = run(
        tmp_path,
        UV + parent + package(style="uv"),
        "uv",
        environment=Environment(policy="explicit-target", python_version="3.15.1"),
    )
    selector = result.dependency_selectors[0]
    assert selector.marker == 'python_version < "3.14"' and selector.marker_semantics == "relative-to-lock-python"
    assert selector.activation == result.relationships[0].activation == "unknown" and selector.extras == ("test",)


def test_pdm_extra_variants_keep_separate_occurrences_and_selected_endpoint(tmp_path):
    parent = package("parent", style="pdm", extra='dependencies=["foo[test]>=1"]\n')
    result = run(tmp_path, PDM + parent + package(style="pdm") + package(style="pdm", extra='extras=["test"]\n'), "pdm")
    assert result.stages.inventory == "complete" and len(result.occurrences) == 3
    child = next(p for p in result.occurrences if p.id == result.relationships[0].child_id)
    assert child.extras == result.dependency_selectors[0].extras == ("test",)


def test_missing_selector_target_is_located_without_inventing_a_package(tmp_path):
    result = run(
        tmp_path, UV + package("parent", style="uv", extra='dependencies=[{name="missing",version="9"}]\n'), "uv"
    )
    assert result.stages.inventory == "partial" and len(result.occurrences) == 1 and not result.relationships
    row = result.dependency_selectors[0]
    assert (
        row.name == "missing" and row.exact_version == "9" and row.disposition == "unresolved" and row.child_id is None
    )
    assert row.reason == "missing-lock-dependency" and result.coverage.inputs[0].disposition == "unresolved"


def test_shared_semantic_budget_clears_all_composed_evidence(tmp_path):
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    result = run(tmp_path, UV + package(style="uv"), "uv", config=DiscoveryConfig(semantic_checks=20))
    assert (
        result.stages.inventory == "failed"
        and not result.occurrences
        and not result.relationships
        and not result.dependency_selectors
    )
    assert "composition-check-budget-exceeded" in result.coverage.refusal_codes


def test_lock_final_epoch_change_clears_all_consumable_evidence(tmp_path, monkeypatch):
    import sourcebastion.inventory.python_locks as locks

    original = locks.parse

    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        (tmp_path / "uv.lock").write_text("changed")
        return result

    monkeypatch.setattr(locks, "parse", changed)
    result = run(tmp_path, UV + package(style="uv"), "uv", unchanged=False)
    assert result.stages.inventory == "failed" and not result.occurrences and not result.dependency_selectors


@pytest.mark.parametrize(
    "field,value",
    [("parent_id", "occurrence:sha256:" + "b" * 64), ("name", "different"), ("exact_version", "9"), ("child_id", None)],
)
def test_structural_selector_validation_refuses_unbound_or_contradictory_edges(tmp_path, field, value):
    result = run(
        tmp_path,
        UV + package("parent", style="uv", extra='dependencies=[{name="foo",version="1"}]\n') + package(style="uv"),
        "uv",
    )
    changed = result.dependency_selectors[0].model_copy(update={field: value})
    with pytest.raises(ValidationError):
        Inventory.model_validate(result.model_copy(update={"dependency_selectors": (changed,)}))


@pytest.mark.parametrize(
    "fixture_id",
    [
        "python-pipfile",
        "python-pipfile-complete",
        "python-poetry",
        "python-poetry-graph",
        "python-pdm",
        "python-pdm-graph",
        "python-uv",
        "python-uv-graph",
        "python-pylock",
        "python-pylock-variant",
        "python-pylock-complete",
        "python-pylock-variant-complete",
    ],
)
def test_frozen_lock_package_identity_subset_without_folder_root_oracle(tmp_path, fixture_id):
    fixture = next(
        f
        for f in json.loads((Path(__file__).parent / "fixtures/inventory/corpus.json").read_text())
        if f["id"] == fixture_id
    )
    for name, text in fixture["files"].items():
        (tmp_path / name).write_text(text)
    config = DiscoveryConfig()
    with Source(tmp_path) as source:
        result = compose_source(
            source,
            source_sha256=SHA,
            producer=Producer(
                name="test", version="1", code_sha256=SHA, registry_sha256=REGISTRY_SHA256, config_sha256=config.sha256
            ),
        )
    assert sorted({"pypi:" + p.name + "@" + p.selected_version for p in result.occurrences}) == sorted(
        fixture["expected"]["packages"]
    )
    assert not result.roots and all(p.root_id is None for p in result.occurrences)


@pytest.mark.parametrize(
    "second",
    [
        '{name="foo",extra=["z","a"]}',
        '{name="foo",version="1",source={registry="https://pypi.org/simple"},extra=["a","z"]}',
    ],
)
def test_duplicate_resolved_uv_selectors_do_not_invent_repeated_edges(tmp_path, second):
    text = (
        UV
        + package("parent", style="uv", extra='dependencies=[{name="foo",extra=["a","z"]},' + second + "]\n")
        + package(style="uv")
    )
    result = run(tmp_path, text, "uv")
    assert result.stages.inventory == "partial" and not result.relationships
    assert len(result.dependency_selectors) == 2 and all(
        s.child_id is None and s.reason == "duplicate-lock-dependency" for s in result.dependency_selectors
    )
    assert all(s.extras == ("a", "z") for s in result.dependency_selectors)


def test_repeated_uv_relative_marker_context_is_not_treated_as_disjoint(tmp_path):
    text = (
        UV
        + package(
            "parent", style="uv", extra='dependencies=[{name="foo"},{name="foo",marker="python_version >= \'3.12\'"}]\n'
        )
        + package(style="uv")
    )
    result = run(tmp_path, text, "uv")
    assert result.stages.inventory == "partial" and not result.relationships
    assert {s.reason for s in result.dependency_selectors} == {"repeated-lock-dependency-context"}


def test_relationship_retention_limit_clears_packages_and_selectors(tmp_path):
    text = (
        UV
        + package("parent", style="uv", extra='dependencies=[{name="foo"},{name="bar"}]\n')
        + package("foo", style="uv")
        + package("bar", style="uv")
    )
    result = run(tmp_path, text, "uv", limits=InventoryLimits(relationships=1))
    assert (
        result.stages.inventory == "failed"
        and not result.occurrences
        and not result.relationships
        and not result.dependency_selectors
    )
    assert "composition-record-budget-exceeded" in result.coverage.refusal_codes


def test_poetry_grammar_cache_clears_on_success_and_refusal(tmp_path):
    from sourcebastion.inventory.poetry_constraints import constraint, version
    from poetry.core.constraints.version import parse_constraint
    from poetry.core.version.pep440.parser import PEP440Parser

    for index in range(25):
        constraint("^1." + str(index))
        version("1." + str(index))
        assert parse_constraint.cache_info().currsize == PEP440Parser.parse.cache_info().currsize == 0
    for raw in ("^1.2 || private-secret", "1" * 129):
        with pytest.raises(InputRefusal):
            constraint(raw)
        assert parse_constraint.cache_info().currsize == PEP440Parser.parse.cache_info().currsize == 0
    result = run(
        tmp_path,
        POETRY + package("parent", extra='[package.dependencies]\nfoo="^1.2"\n') + package("foo", "1.2.5"),
        "poetry",
    )
    assert result.stages.inventory == "complete"
    assert parse_constraint.cache_info().currsize == PEP440Parser.parse.cache_info().currsize == 0


@pytest.mark.parametrize(
    "style,header,dependency",
    [("poetry", POETRY, '[package.dependencies]\nfoo="*"\n'), ("pdm", PDM, 'dependencies=["foo[test]>=1"]\n')],
)
def test_selected_child_cannot_change_group_scope_or_exact_extra_variant(tmp_path, style, header, dependency):
    result = run(
        tmp_path,
        header
        + package("parent", style=style, extra=dependency)
        + package(style=style, extra='extras=["test"]\n' if style == "pdm" else ""),
        style,
    )
    assert len(result.relationships) == 1
    child_id = result.relationships[0].child_id
    changes = [{"groups": ("another",)}, {"scopes": ("another",)}]
    if style == "pdm":
        changes.append({"extras": ()})
    for values in changes:
        rows = tuple(p.model_copy(update=values) if p.id == child_id else p for p in result.occurrences)
        with pytest.raises(ValidationError, match="contradictory-selector-endpoint"):
            Inventory.model_validate(result.model_copy(update={"occurrences": rows}))


def test_unresolved_selector_cannot_be_promoted_to_complete_graph(tmp_path):
    result = run(tmp_path, UV + package("parent", style="uv", extra='dependencies=[{name="missing"}]\n'), "uv")
    with pytest.raises(ValidationError, match="unresolved-selector-cannot-prove-complete-graph"):
        Inventory.model_validate(
            result.model_copy(update={"coverage": result.coverage.model_copy(update={"graph": "complete"})})
        )


@pytest.mark.parametrize("hashes", [None, []])
def test_pipfile_missing_artifact_hashes_preserves_pin_with_partial_coverage(tmp_path, hashes):
    fields = {"version": "==1"}
    if hashes is not None:
        fields["hashes"] = hashes
    text = json.dumps(
        {
            "_meta": {"pipfile-spec": 6, "hash": {"sha256": SHA}, "requires": {}, "sources": []},
            "default": {"foo": fields},
        }
    )
    result = run(tmp_path, text, "pipfile")
    assert result.stages.inventory == "partial" and len(result.occurrences) == 1
    assert result.occurrences[0].selected_version == "1" and not result.occurrences[0].hashes
    assert (
        result.coverage.inputs[0].disposition == "unsupported"
        and result.coverage.inputs[0].reason == "missing-lock-source"
    )


@pytest.mark.parametrize("duplicate", [False, True])
def test_resolved_selector_requires_exactly_one_matching_canonical_edge(tmp_path, duplicate):
    from sourcebastion.inventory.contract import identifier

    result = run(
        tmp_path, UV + package("parent", style="uv", extra='dependencies=[{name="foo"}]\n') + package(style="uv"), "uv"
    )
    assert len(result.relationships) == 1
    relationships = (
        (
            result.relationships[0],
            result.relationships[0].model_copy(update={"id": identifier("relationship", ["duplicate"])}),
        )
        if duplicate
        else ()
    )
    with pytest.raises(ValidationError, match="selector-requires-exactly-one-evidenced-edge"):
        Inventory.model_validate(result.model_copy(update={"relationships": relationships}))
