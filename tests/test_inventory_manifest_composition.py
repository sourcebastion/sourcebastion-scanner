"""Canonical static metadata, scope and target evidence without execution."""

import hashlib
import json

import pytest

from sourcebastion.inventory.compose_source import compose_source
from sourcebastion.inventory.contract import Environment, InventoryLimits, Producer, canonical_bytes
from sourcebastion.inventory.inputs import Source
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256

SHA = "a" * 64


def run(root, *, environment=None, config=None, limits=None):
    config = config or DiscoveryConfig()
    with Source(root) as source:
        return compose_source(
            source,
            source_sha256=SHA,
            producer=Producer(
                name="test", version="1", code_sha256=SHA, registry_sha256=REGISTRY_SHA256, config_sha256=config.sha256
            ),
            environment=environment,
            config=config,
            limits=limits,
        )


def files(root, values):
    for name, value in values.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(value)


@pytest.mark.parametrize(
    "path,text",
    [
        ("pyproject.toml", '[project]\nname="my-App"\nversion="v1.0"\ndependencies=["Pip==26.0.1"]\n'),
        ("setup.cfg", "[metadata]\nname = my-App\nversion = v1.0\n[options]\ninstall_requires =\n    Pip==26.0.1\n"),
        (
            "setup.py",
            'from setuptools import setup\nsetup(name="my-App",version="v1.0",install_requires=["Pip==26.0.1"])\n',
        ),
    ],
)
def test_static_manifest_proves_project_and_declarations_but_no_install_or_edges(tmp_path, path, text):
    files(tmp_path, {path: text})
    result = run(tmp_path)
    assert result.stages.inventory == "complete"
    assert len(result.roots) == len(result.applications) == len(result.occurrences) == 1
    row = result.occurrences[0]
    assert row.name == "pip" and row.selected_version == "26.0.1" and row.evidence_kind == "declared"
    assert row.root_id == result.roots[0].id and row.installed_environment_id is None and row.directness == "direct"
    assert row.scopes == ("runtime",) and row.selection_declaration_ids == (result.declarations[0].id,)
    assert result.applications[0].name == "my-app" and result.applications[0].version == "1.0"
    assert result.roots[0].path == "." and not result.relationships
    assert result.coverage.inputs[0].source_sha256 == hashlib.sha256(text.encode()).hexdigest()
    assert result.coverage.inputs[0].root_ids == (result.roots[0].id,)
    assert result.coverage.graph == result.coverage.environment == "unknown"
    assert canonical_bytes(result) == canonical_bytes(run(tmp_path))


def test_one_discovery_combines_requirements_and_manifest_without_guessing_shared_ownership(tmp_path, monkeypatch):
    import sourcebastion.inventory.compose_requirements as composer

    original, calls = composer.discover, 0

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(composer, "discover", counted)
    files(
        tmp_path,
        {
            "requirements.txt": "pip==26.0.1\n",
            "pyproject.toml": '[project]\nname="app"\nversion="1"\ndependencies=["pip==26.0.1"]\n',
        },
    )
    result = run(tmp_path)
    assert calls == 1 and result.stages.inventory == "complete" and len(result.occurrences) == 2
    assert {p.root_id for p in result.occurrences} == {None, result.roots[0].id}
    assert len(result.analysis_scopes) == 2 and not result.relationships


def test_requires_python_optional_group_and_marker_remain_separate_conditions(tmp_path):
    files(
        tmp_path,
        {
            "pyproject.toml": '[project]\nname="app"\nversion="1"\nrequires-python=">=3.12,<3.13"\ndependencies=["pip==26.0.1"]\n[project.optional-dependencies]\ntest=["pytest==8.3.3; sys_platform == \\"linux\\""]\n[build-system]\nrequires=["setuptools==80.0"]\n'
        },
    )
    result = run(tmp_path)
    rows = {p.name: p for p in result.occurrences}
    assert rows["pip"].activation == "unknown" and rows["pytest"].activation == "unknown"
    assert rows["setuptools"].scopes == ("build",) and rows["setuptools"].activation == "active"
    assert rows["pytest"].groups == ("test",) and rows["pytest"].extras == ()
    assert {a.kind for a in result.applicability} == {"python-version", "group"}
    target = run(tmp_path, environment=Environment(policy="explicit-target", python_version="3.12.9", platform="linux"))
    assert {p.name: p.activation for p in target.occurrences} == {
        "pip": "active",
        "pytest": "unknown",
        "setuptools": "active",
    }
    other = run(tmp_path, environment=Environment(policy="explicit-target", python_version="3.13.1", platform="linux"))
    assert {p.name: p.activation for p in other.occurrences} == {
        "pip": "inactive",
        "pytest": "inactive",
        "setuptools": "active",
    }
    minor = run(tmp_path, environment=Environment(policy="explicit-target", python_version="3.12", platform="linux"))
    assert {p.name: p.activation for p in minor.occurrences}["pip"] == "unknown"


def test_manifest_range_without_pin_stays_unselected(tmp_path):
    files(tmp_path, {"pyproject.toml": '[project]\nname="app"\nversion="1"\ndependencies=["pip>=26"]\n'})
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and result.occurrences[0].selected_version is None
    assert result.occurrences[0].selection_declaration_ids == ()


def test_project_metadata_is_required_before_assigning_root_ownership(tmp_path):
    files(tmp_path, {"setup.py": 'from setuptools import setup\nsetup(install_requires=["pip==26.0.1"])\n'})
    result = run(tmp_path)
    assert result.stages.inventory == "complete" and not result.roots and not result.applications
    assert result.occurrences[0].root_id is None and result.occurrences[0].analysis_scope_id


def test_empty_explicit_project_and_metadata_only_file_have_different_coverage(tmp_path):
    files(tmp_path, {"pyproject.toml": '[project]\nname="app"\nversion="1"\ndependencies=[]\n'})
    assert run(tmp_path).stages.inventory == "complete"
    files(tmp_path, {"pyproject.toml": "[tool.black]\nline-length=110\n"})
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and not result.occurrences and not result.roots
    assert result.coverage.inputs[0].reason == "no-project-dependency-evidence"


def test_conflicting_same_scope_declarations_do_not_select_versions(tmp_path):
    files(tmp_path, {"pyproject.toml": '[project]\nname="app"\nversion="1"\ndependencies=["pip==26.0.1","pip>=27"]\n'})
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and len(result.declarations) == 2
    assert "conflicting-manifest-declarations" in result.coverage.refusal_codes
    assert all(p.selected_version is None for p in result.occurrences)


def test_build_and_runtime_contexts_do_not_borrow_each_others_pins(tmp_path):
    files(
        tmp_path,
        {
            "pyproject.toml": '[project]\nname="app"\nversion="1"\ndependencies=["pip>=26"]\n[build-system]\nrequires=["pip==26.0.1"]\n'
        },
    )
    result = run(tmp_path)
    assert {p.scopes: p.selected_version for p in result.occurrences} == {("runtime",): None, ("build",): "26.0.1"}


def test_same_marker_range_can_select_a_compatible_source_pin(tmp_path):
    files(tmp_path, {"pyproject.toml": '[project]\nname="app"\nversion="1"\ndependencies=["pip>=26","pip==26.0.1"]\n'})
    result = run(tmp_path)
    assert result.stages.inventory == "complete" and {p.selected_version for p in result.occurrences} == {"26.0.1"}
    assert all(len(p.selection_declaration_ids) == 2 for p in result.occurrences)


def test_dynamic_metadata_refuses_without_running_project_code(tmp_path):
    files(tmp_path, {"setup.py": 'from pathlib import Path\nPath("EXECUTED").write_text("bad")\n'})
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and not result.occurrences
    assert not (tmp_path / "EXECUTED").exists() and result.coverage.inputs[0].disposition == "unsupported"


def test_unknown_non_python_input_cannot_be_promoted_by_valid_manifest(tmp_path):
    files(
        tmp_path,
        {
            "pyproject.toml": '[project]\nname="app"\nversion="1"\ndependencies=["pip==26.0.1"]\n',
            "Cargo.lock": 'version = 4\n[[package]]\nname = "fixture"\nversion = "1.0.0"\n',
        },
    )
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and result.occurrences[0].selected_version == "26.0.1"
    assert {r.source_path: r.disposition for r in result.coverage.inputs}["Cargo.lock"] == "unsupported"


def test_final_manifest_epoch_failure_clears_every_kind_of_consumable_evidence(tmp_path, monkeypatch):
    from sourcebastion.inventory import python_manifests

    original = python_manifests.parse
    files(
        tmp_path,
        {
            "requirements.txt": "setuptools==80.0\n",
            "pyproject.toml": '[project]\nname="app"\nversion="1"\ndependencies=["pip==26.0.1"]\n',
        },
    )

    def changed(*args, **kwargs):
        doc = original(*args, **kwargs)
        (tmp_path / "pyproject.toml").write_text('[project]\nname="changed"\nversion="2"\n')
        return doc

    monkeypatch.setattr(python_manifests, "parse", changed)
    result = run(tmp_path)
    assert result.stages.inventory == "failed"
    assert (
        result.occurrences == result.declarations == result.roots == result.applications == result.applicability == ()
    )


def test_manifest_and_pip_share_occurrence_and_structure_limits(tmp_path):
    files(
        tmp_path,
        {
            "requirements.txt": "setuptools==80.0\n",
            "pyproject.toml": '[project]\nname="app"\nversion="1"\ndependencies=["pip==26.0.1"]\n',
        },
    )
    result = run(tmp_path, limits=InventoryLimits(occurrences=1))
    assert result.stages.inventory == "failed" and not result.occurrences
    result = run(tmp_path, limits=InventoryLimits(export_nodes=60))
    assert result.stages.inventory == "failed" and not result.occurrences


def test_disjoint_manifest_markers_preserve_alternative_pins(tmp_path):
    dependencies = ['pip==26.0.1; python_version < "3.13"', 'pip==26.2; python_version >= "3.13"']
    files(
        tmp_path,
        {"pyproject.toml": '[project]\nname="app"\nversion="1"\ndependencies=' + json.dumps(dependencies) + "\n"},
    )
    result = run(tmp_path)
    assert result.stages.inventory == "complete"
    assert {p.selected_version for p in result.occurrences} == {"26.0.1", "26.2"}
    assert {p.activation for p in result.occurrences} == {"unknown"}


def test_overlapping_manifest_conditions_do_not_admit_selected_versions(tmp_path):
    dependencies = ['pip==26.0.1; python_version >= "3.12"', 'pip==26.2; python_version < "3.14"']
    files(
        tmp_path,
        {"pyproject.toml": '[project]\nname="app"\nversion="1"\ndependencies=' + json.dumps(dependencies) + "\n"},
    )
    result = run(tmp_path)
    assert result.stages.inventory == "partial"
    assert "overlapping-manifest-context-unresolved" in result.coverage.refusal_codes
    assert all(p.selected_version is None for p in result.occurrences)


def test_manifest_selection_work_cannot_get_a_fresh_semantic_allowance(tmp_path, monkeypatch):
    from packaging.specifiers import SpecifierSet

    dependencies = ["pip>=0"] * 50 + ["pip==1"] + ["pip>=0." + str(n) for n in range(1, 100)]
    files(
        tmp_path,
        {"pyproject.toml": '[project]\nname="app"\nversion="1"\ndependencies=' + json.dumps(dependencies) + "\n"},
    )
    original, calls = SpecifierSet.contains, 0

    def counted(selector, *args, **kwargs):
        nonlocal calls
        calls += 1
        return original(selector, *args, **kwargs)

    monkeypatch.setattr(SpecifierSet, "contains", counted)
    result = run(tmp_path, config=DiscoveryConfig(semantic_checks=1131))
    assert result.stages.inventory == "failed" and result.occurrences == result.declarations == ()
    assert calls <= 1131


def test_project_target_does_not_bind_build_interpreter_or_platform(tmp_path):
    build = ['setuptools==80.0; python_version < "3.13"', 'wheel==0.45.1; sys_platform == "linux"']
    files(
        tmp_path,
        {
            "pyproject.toml": '[project]\nname="app"\nversion="1"\nrequires-python=">=3.13"\n[build-system]\nrequires='
            + json.dumps(build)
            + "\n"
        },
    )
    result = run(tmp_path, environment=Environment(policy="explicit-target", python_version="3.13.1", platform="linux"))
    assert len(result.occurrences) == 2 and {p.activation for p in result.occurrences} == {"unknown"}
    assert all(p.scopes == ("build",) for p in result.occurrences)
