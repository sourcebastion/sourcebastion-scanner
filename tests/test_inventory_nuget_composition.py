"""Source-authored NuGet expectations, alternatives and hostile input refusals."""

import base64
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest

from sourcebastion.inventory import compose_nuget, nuget_sources
from sourcebastion.inventory.compose_source import compose_source
from sourcebastion.inventory.contract import Inventory, InventoryLimits, Producer, canonical_bytes
from sourcebastion.inventory.inputs import Source
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256

HASH = base64.b64encode(bytes(range(64))).decode()


def package(version="1.2.3", *, kind="Direct", requested="[1.0.0, )", dependencies=None):
    result = {"type": kind, "resolved": version, "contentHash": HASH}
    if kind == "Direct":
        result["requested"] = requested
    if dependencies is not None:
        result["dependencies"] = dependencies
    return result


def run(root, *, config=None, limits=None):
    config = config or DiscoveryConfig()
    with Source(root) as source:
        return compose_source(
            source,
            source_sha256="a" * 64,
            producer=Producer(
                name="test",
                version="1",
                code_sha256="a" * 64,
                registry_sha256=REGISTRY_SHA256,
                config_sha256=config.sha256,
            ),
            config=config,
            limits=limits,
        )


def write(root, targets, *, version=1):
    (root / "packages.lock.json").write_text(json.dumps({"version": version, "dependencies": targets}))


@pytest.mark.parametrize("version", [1, 2])
def test_locked_source_versions_hashes_and_edges_are_located_not_installed(tmp_path, monkeypatch, version):
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("project execution"))
    write(
        tmp_path,
        {
            "net8.0": {
                "Parent": package(dependencies={"Child": "[2.0.0,3.0.0)"}),
                "Child": package("2.1.0", kind="Transitive"),
            }
        },
        version=version,
    )
    result = run(tmp_path)
    assert result.stages.inventory == "complete"
    assert {(p.name, p.selected_version, p.directness) for p in result.occurrences} == {
        ("parent", "1.2.3", "direct"),
        ("child", "2.1.0", "transitive"),
    }
    assert all(
        p.hashes[0].algorithm == "sha512" and p.hashes[0].digest == bytes(range(64)).hex() for p in result.occurrences
    )
    assert not result.roots and not result.applications and not result.installed_environments
    assert all(
        p.root_id is p.installed_environment_id is None and p.activation == "unknown" for p in result.occurrences
    )
    (edge,) = result.relationships
    parent = next(p for p in result.occurrences if p.id == edge.parent_id)
    child = next(p for p in result.occurrences if p.id == edge.child_id)
    assert (parent.name, child.name) == ("parent", "child")
    (selector,) = result.dependency_selectors
    assert selector.declared_range == "[2.0.0,3.0.0)" and selector.dialect == "nuget-release-range-1"
    assert edge.source.locator == "/dependencies/net8.0/Parent/dependencies/Child"
    assert result.coverage.graph == "partial" and result.coverage.environment == "unknown"
    assert canonical_bytes(Inventory.model_validate_json(canonical_bytes(result))) == canonical_bytes(result)
    assert canonical_bytes(run(tmp_path)) == canonical_bytes(result)


def test_frameworks_rids_and_multiple_roots_keep_equal_purls_distinct(tmp_path):
    for name in ("one", "two"):
        root = tmp_path / name
        root.mkdir()
        write(
            root,
            {
                "net8.0": {"Child": package()},
                "net9.0": {"Child": package("2.0.0")},
                "net8.0/linux-x64": {"Child": package()},
            },
        )
    result = run(tmp_path)
    assert len(result.occurrences) == len({p.id for p in result.occurrences}) == 6
    assert len({p.analysis_scope_id for p in result.occurrences}) == 6
    assert len({p.purl for p in result.occurrences}) == 2
    assert not result.relationships and not result.roots


@pytest.mark.parametrize(
    "expression,version,answer",
    [
        ("1.0", "2.0.0", True),
        ("[1.0]", "1.0.0.0", True),
        ("[1.0]", "2.0", False),
        ("[1,2)", "1.9", True),
        ("[1,2)", "2.0", False),
        ("(, 2.0]", "2", True),
        ("(1,2]", "1", False),
        ("[2,1]", "2", None),
        ("[1,1)", "1", None),
        ("[1,)", "1.2.3", True),
        ("[1,]", "1", None),
        ("(,)", "1", None),
        ("1.*", "1.2.3", None),
        ("[1,2)", "1.2.3-rc.1", None),
        ("https://u:p@host", "1", None),
    ],
)
def test_conservative_release_range_grammar(expression, version, answer):
    assert nuget_sources.satisfies(version, expression) is answer


@pytest.mark.parametrize(
    "expression,child_version,reason",
    [
        ("3.0", "2.0", "contradictory-nuget-dependency-range"),
        ("2.*", "2.0", "unassessed-nuget-dependency-range"),
        ("[2,3)", "2.0-rc.1", "unassessed-nuget-dependency-range"),
    ],
)
def test_uncertain_edges_preserve_selector_without_guessing_endpoint(tmp_path, expression, child_version, reason):
    write(
        tmp_path,
        {
            "net8.0": {
                "Parent": package(dependencies={"Child": expression}),
                "Child": package(child_version, kind="Transitive"),
            }
        },
    )
    result = run(tmp_path)
    assert len(result.occurrences) == 2 and not result.relationships and result.stages.inventory == "partial"
    (selector,) = result.dependency_selectors
    assert selector.child_id is None and selector.reason == reason and selector.declared_range == expression


def test_rid_delta_does_not_borrow_base_framework_endpoint(tmp_path):
    write(
        tmp_path,
        {"net8.0": {"Child": package()}, "net8.0/linux-x64": {"Parent": package(dependencies={"Child": "1.0"})}},
    )
    result = run(tmp_path)
    assert len(result.occurrences) == 2 and not result.relationships
    assert result.dependency_selectors[0].reason == "missing-nuget-lock-endpoint"


@pytest.mark.parametrize("hash_value", [None, "fixture", "A" * 100000, HASH.rstrip("=")])
def test_invalid_hash_keeps_source_version_but_refuses_complete_coverage(tmp_path, hash_value):
    value = package()
    value["contentHash"] = hash_value
    write(tmp_path, {"net8.0": {"Child": value}})
    result = run(tmp_path)
    assert len(result.occurrences) == 1 and not result.occurrences[0].hashes
    assert result.occurrences[0].selected_version == "1.2.3" and result.stages.inventory == "partial"
    assert result.coverage.inputs[0].reason == "unassessed-nuget-content-hash"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(version=True),
        lambda d: d.update(version=3),
        lambda d: d.update(dependencies={}),
        lambda d: d.update(unknown="https://user:secret@host"),
        lambda d: d["dependencies"]["net8.0"].update(child=package()),
        lambda d: d["dependencies"]["net8.0"]["Child"].update(resolved="*"),
        lambda d: d["dependencies"]["net8.0"]["Child"].update(requested="[9,10)"),
    ],
)
def test_refused_input_never_admits_selected_prefix_or_secrets(tmp_path, mutate):
    document = {"version": 1, "dependencies": {"net8.0": {"Child": package()}}}
    mutate(document)
    (tmp_path / "packages.lock.json").write_text(json.dumps(document))
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and [p.name for p in result.occurrences] == ["pip"]
    assert b"secret" not in canonical_bytes(result)


def test_duplicate_keys_and_deep_json_are_refused(tmp_path):
    for content in ('{"version":1,"version":1,"dependencies":{}}', "[" * 33 + "0" + "]" * 33):
        (tmp_path / "packages.lock.json").write_text(content)
        result = run(tmp_path)
        assert not result.occurrences and result.stages.inventory != "complete"


def test_record_budget_refuses_all_mixed_inventory(tmp_path):
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    write(tmp_path, {"net8.0": {"Child": package()}})
    result = run(tmp_path, limits=InventoryLimits(occurrences=1))
    assert result.stages.inventory == "failed" and not result.occurrences and not result.declarations
    assert "nuget-source-record-budget-exceeded" in result.coverage.refusal_codes


def test_source_mutation_refuses_complete_mixed_result(tmp_path, monkeypatch):
    write(tmp_path, {"net8.0": {"Child": package()}})
    original = compose_nuget.nuget_sources.parse

    def changed(content, **kwargs):
        value = original(content, **kwargs)
        (tmp_path / "packages.lock.json").write_text("{}")
        return value

    monkeypatch.setattr(compose_nuget.nuget_sources, "parse", changed)
    result = run(tmp_path)
    assert result.stages.inventory == "failed" and not result.occurrences


def test_shared_semantic_exhaustion_clears_prior_mixed_records(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    write(tmp_path, {"net8.0": {"Child": package()}})
    original = compose_nuget.extend

    def exhausted(state):
        assert state.occurrences
        state.step(state.limits.semantic_checks)
        original(state)

    monkeypatch.setattr(compose_nuget, "extend", exhausted)
    result = run(tmp_path)
    assert result.stages.inventory == "failed" and not result.occurrences
    assert "composition-check-budget-exceeded" in result.coverage.refusal_codes


@pytest.mark.parametrize("field", ["requested", "dependencies"])
def test_private_uri_cannot_enter_canonical_selectors(tmp_path, field):
    value = package()
    value[field] = (
        "https://user:secret@host/package" if field == "requested" else {"Child": "https://user:secret@host/package"}
    )
    write(tmp_path, {"net8.0": {"Parent": value, "Child": package()}})
    result = run(tmp_path)
    assert not result.occurrences and not result.dependency_selectors
    assert b"secret" not in canonical_bytes(result) and b"host/package" not in canonical_bytes(result)


def test_project_reference_does_not_become_registry_package(tmp_path):
    write(tmp_path, {"net8.0": {"Local.Project": {"type": "Project", "resolved": "1.0.0"}, "Child": package()}})
    result = run(tmp_path)
    assert [p.name for p in result.occurrences] == ["child"]
    assert result.stages.inventory == "partial"
    assert result.coverage.inputs[0].reason == "unsupported-nuget-project-or-package-type"


@pytest.mark.parametrize("kind", [None, True, {}, [], 1])
def test_malformed_package_type_is_visible_omission(tmp_path, kind):
    value = package()
    value["type"] = kind
    write(tmp_path, {"net8.0": {"Child": value}})
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and not result.occurrences
    assert result.coverage.inputs[0].reason == "unsupported-nuget-project-or-package-type"


def test_selector_cannot_borrow_other_framework_scopes(tmp_path):
    from pydantic import ValidationError

    write(tmp_path, {"net8.0": {"Parent": package(dependencies={"Child": "1.0"}), "Child": package()}})
    result = run(tmp_path)
    selector = result.dependency_selectors[0].model_copy(update={"scopes": ("net9.0",)})
    forged = result.model_copy(update={"dependency_selectors": (selector,)})
    with pytest.raises(ValidationError, match="selector-requires-same-lock-parent"):
        canonical_bytes(forged)


def test_original_dotnet_fixture_preserves_expected_package_with_honest_hash_coverage(tmp_path):
    checkout = Path(__file__).resolve().parents[1]
    expected = next(
        c
        for c in json.loads((checkout / "evaluation/m046/canonical-source-expectations-v1.json").read_text())["cases"]
        if c["case"] == "dotnet-lock"
    )
    for fixture in expected["fixture_files"]:
        (tmp_path / fixture["path"]).write_text(fixture["utf8"])
    result = run(tmp_path)
    assert [(p.name, p.selected_version) for p in result.occurrences] == [("newtonsoft.json", "13.0.3")]
    spec = importlib.util.spec_from_file_location(
        "nuget_comparator", checkout / "scripts/verify-inventory-expectations.py"
    )
    comparator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(comparator)
    comparator.compare(expected, json.loads(canonical_bytes(result)))
