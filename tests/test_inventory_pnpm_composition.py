"""Canonical source endpoints and context separation for pnpm9."""

import copy
from pathlib import Path
import pytest
import yaml
from sourcebastion.inventory.compose_source import compose_source
from sourcebastion.inventory.contract import Producer, canonical_bytes
from sourcebastion.inventory.inputs import InputRefusal, Source
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256

SHA = "a" * 64


def run(root, *, config=None, limits=None):
    config = config or DiscoveryConfig()
    with Source(root) as source:
        return compose_source(
            source,
            source_sha256=SHA,
            producer=Producer(
                name="test", version="1", code_sha256=SHA, registry_sha256=REGISTRY_SHA256, config_sha256=config.sha256
            ),
            config=config,
            limits=limits,
        )


def fixture():
    return {
        "lockfileVersion": "9.0",
        "importers": {
            ".": {"dependencies": {"alpha": {"specifier": "^1.0.0", "version": "1.2.3"}}},
        },
        "packages": {
            name: {"resolution": {"integrity": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}
            for name in ("alpha@1.2.3", "beta@2.0.0")
        },
        "snapshots": {"alpha@1.2.3": {"dependencies": {"beta": "2.0.0"}}, "beta@2.0.0": {}},
    }


def write(root, *documents):
    (root / "pnpm-lock.yaml").write_text(yaml.safe_dump_all(documents, sort_keys=False))


def test_exact_source_edges_scopes_and_reproducibility(tmp_path):
    write(tmp_path, fixture())
    result = run(tmp_path)
    assert len(result.occurrences) == 2 and len(result.relationships) == 1
    first, second = sorted(result.occurrences, key=lambda value: value.name)
    assert (first.directness, second.directness) == ("direct", "transitive")
    assert first.scopes == second.scopes == ("runtime",)
    assert result.relationships[0].parent_id == first.id
    assert result.relationships[0].child_id == second.id
    assert result.dependency_selectors[0].exact_version == "2.0.0"
    assert result.coverage.graph == "partial"
    assert result.stages.inventory == "complete"
    assert not result.roots and not result.applications and not result.installed_environments
    assert all(value.root_id is None and value.activation == "unknown" for value in result.occurrences)
    assert canonical_bytes(result) == canonical_bytes(run(tmp_path))


def test_two_documents_with_identical_importer_keys_remain_separate(tmp_path):
    first = fixture()
    first["importers"]["."]["configDependencies"] = first["importers"]["."].pop("dependencies")
    write(tmp_path, first, fixture())
    result = run(tmp_path)
    assert len(result.occurrences) == 4 and len(result.relationships) == 2
    assert len({value.analysis_scope_id for value in result.occurrences}) == 2
    assert {value.scopes for value in result.occurrences} == {("runtime",), ("build",)}
    by_id = {value.id: value for value in result.occurrences}
    assert all(
        by_id[edge.parent_id].analysis_scope_id == by_id[edge.child_id].analysis_scope_id
        for edge in result.relationships
    )


def test_multiple_importers_do_not_share_occurrence_ownership(tmp_path):
    data = fixture()
    data["importers"]["packages/tool"] = {"devDependencies": {"alpha": {"specifier": "^1", "version": "1.2.3"}}}
    write(tmp_path, data)
    result = run(tmp_path)
    assert len(result.occurrences) == 4 and len(result.relationships) == 2
    assert {value.scopes for value in result.occurrences} == {("runtime",), ("development",)}
    assert len({value.analysis_scope_id for value in result.occurrences}) == 2


def test_peer_variants_require_exact_context_key(tmp_path):
    data = fixture()
    data["importers"]["."]["dependencies"]["alpha"]["version"] = "1.2.3(peer@1.0.0)"
    data["snapshots"] = {
        "alpha@1.2.3(peer@1.0.0)": {"dependencies": {"beta": "2.0.0"}},
        "alpha@1.2.3(peer@2.0.0)": {},
        "beta@2.0.0": {},
    }
    write(tmp_path, data)
    result = run(tmp_path)
    alpha = [value for value in result.occurrences if value.name == "alpha"]
    assert len(alpha) == 2 and len({value.id for value in alpha}) == 2
    assert {value.directness for value in alpha} == {"direct", "unknown"}
    assert len(result.relationships) == 1


def test_missing_peer_context_does_not_fallback_to_equal_version(tmp_path):
    data = fixture()
    data["importers"]["."]["dependencies"]["alpha"]["version"] = "1.2.3(peer@missing)"
    write(tmp_path, data)
    result = run(tmp_path)
    assert result.stages.inventory == "partial"
    assert all(value.directness == "unknown" for value in result.occurrences)
    assert all(value.analysis_scope_id == result.occurrences[0].analysis_scope_id for value in result.occurrences)


def test_unowned_graph_closes_over_owned_package_in_separate_scope(tmp_path):
    data = fixture()
    data["packages"]["gamma@3.0.0"] = {
        "resolution": {"integrity": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
    }
    data["snapshots"]["gamma@3.0.0"] = {"dependencies": {"beta": "2.0.0"}}
    write(tmp_path, data)
    result = run(tmp_path)
    assert len(result.occurrences) == 4 and len(result.relationships) == 2
    beta = [value for value in result.occurrences if value.name == "beta"]
    assert len(beta) == 2 and {value.directness for value in beta} == {"unknown", "transitive"}


def test_optional_dependency_scope_stays_optional(tmp_path):
    data = fixture()
    data["snapshots"]["alpha@1.2.3"]["optionalDependencies"] = data["snapshots"]["alpha@1.2.3"].pop("dependencies")
    write(tmp_path, data)
    result = run(tmp_path)
    beta = next(value for value in result.occurrences if value.name == "beta")
    assert beta.scopes == ("optional",)
    assert result.relationships[0].scopes == ("optional",)


def test_unsupported_uri_is_private_and_selection_unresolved(tmp_path):
    data = fixture()
    data["importers"]["."]["dependencies"]["alpha"]["specifier"] = "https://user:secret@example.invalid/a.tgz"
    write(tmp_path, data)
    result = run(tmp_path)
    assert result.stages.inventory == "partial"
    assert result.declarations[0].declared_range is None
    assert b"secret" not in canonical_bytes(result)
    assert not any(value.directness == "direct" for value in result.occurrences)


def test_invalid_selected_version_never_becomes_a_package(tmp_path):
    data = fixture()
    data["packages"]["huge@99999999999999999.0.0"] = {
        "resolution": {"integrity": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
    }
    data["snapshots"]["huge@99999999999999999.0.0"] = {}
    write(tmp_path, data)
    result = run(tmp_path)
    assert result.stages.inventory == "partial"
    assert not any(value.name == "huge" for value in result.occurrences)


def test_global_occurrence_limit_clears_all_mixed_facts(tmp_path):
    from sourcebastion.inventory.contract import InventoryLimits

    write(tmp_path, fixture())
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n")
    result = run(tmp_path, limits=InventoryLimits(occurrences=2))
    assert result.stages.inventory == "failed"
    assert not result.occurrences and not result.declarations and not result.relationships


def test_epoch_failure_clears_all_mixed_facts(tmp_path, monkeypatch):
    write(tmp_path, fixture())
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n")

    def changed(self):
        raise InputRefusal("changed-source-input")

    monkeypatch.setattr(Source, "validate", changed)
    result = run(tmp_path)
    assert result.stages.inventory == "failed" and not result.occurrences and not result.relationships


def test_one_discovery_and_no_project_execution(tmp_path, monkeypatch):
    from sourcebastion.inventory import compose_requirements

    original = compose_requirements.discover
    calls = []

    def discover(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(compose_requirements, "discover", discover)
    write(tmp_path, fixture())
    (tmp_path / "pnpmfile.cjs").write_text("throw Error('executed')")
    run(tmp_path)
    assert calls == [1]


@pytest.mark.parametrize("resolution", [None, {}, {"revision": "1"}])
def test_incomplete_package_resolution_never_reports_complete_inventory(tmp_path, resolution):
    data = fixture()
    data["packages"]["alpha@1.2.3"] = {} if resolution is None else {"resolution": resolution}
    write(tmp_path, data)
    result = run(tmp_path)
    assert result.stages.inventory == "partial"
    assert result.coverage.inputs[0].reason == "incomplete-pnpm-package-resolution"
    assert {value.name for value in result.occurrences} == {"alpha", "beta"}
