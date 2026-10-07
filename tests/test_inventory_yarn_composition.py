"""Exact descriptor binding, alias grouping and source-only Yarn evidence."""

import copy
import pytest
import yaml
from sourcebastion.inventory.compose_source import compose_source
from sourcebastion.inventory.contract import Producer, canonical_bytes, InventoryLimits
from sourcebastion.inventory.inputs import Source, InputRefusal
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256

SHA = "a" * 64
LEGACY = """# yarn lockfile v1

"alpha@^1":
  version "1.2.3"
  resolved "https://registry.npmjs.org/alpha/-/alpha-1.2.3.tgz"
  dependencies:
    beta "^2"

"beta@^2":
  version "2.0.0"
  resolved "https://registry.npmjs.org/beta/-/beta-2.0.0.tgz"
"""


def modern():
    return {
        "__metadata": {"version": "10", "cacheKey": "10c0"},
        "alpha@npm:^1": {
            "version": "1.2.3",
            "resolution": "alpha@npm:1.2.3",
            "linkType": "hard",
            "languageName": "node",
            "dependencies": {"beta": "npm:^2"},
        },
        "beta@npm:^2": {"version": "2.0.0", "resolution": "beta@npm:2.0.0", "linkType": "hard", "languageName": "node"},
    }


def run(root, *, limits=None, config=None):
    config = config or DiscoveryConfig()
    with Source(root) as source:
        return compose_source(
            source,
            source_sha256=SHA,
            producer=Producer(
                name="test", version="1", code_sha256=SHA, registry_sha256=REGISTRY_SHA256, config_sha256=config.sha256
            ),
            limits=limits,
            config=config,
        )


def write(root, content):
    (root / "yarn.lock").write_text(content if type(content) is str else yaml.safe_dump(content, sort_keys=False))


@pytest.mark.parametrize("content", [LEGACY, modern()])
def test_registry_source_graph_and_reproducibility(tmp_path, content):
    write(tmp_path, content)
    result = run(tmp_path)
    assert result.stages.inventory == "complete" and len(result.occurrences) == 2
    assert len(result.relationships) == 1 and len(result.dependency_selectors) == 1
    by_id = {value.id: value for value in result.occurrences}
    edge = result.relationships[0]
    assert (by_id[edge.parent_id].name, by_id[edge.child_id].name) == ("alpha", "beta")
    assert edge.scopes == ("runtime",)
    assert not result.roots and not result.applications and not result.installed_environments
    assert all(
        value.root_id is None and value.directness == "unknown" and value.activation == "unknown"
        for value in result.occurrences
    )
    assert canonical_bytes(result) == canonical_bytes(run(tmp_path))


def test_alias_keys_of_one_entry_keep_one_occurrence(tmp_path):
    content = LEGACY.replace('"alpha@^1":', '"alpha@^1", "alpha@~1":')
    write(tmp_path, content)
    result = run(tmp_path)
    assert len(result.occurrences) == 2 and len(result.relationships) == 1


def test_identical_separate_entries_never_merge_by_purl(tmp_path):
    content = (
        LEGACY + '\n"beta@~2":\n  version "2.0.0"\n  resolved "https://registry.npmjs.org/beta/-/beta-2.0.0.tgz"\n'
    )
    write(tmp_path, content)
    result = run(tmp_path)
    assert len(result.occurrences) == 3
    beta = [value for value in result.occurrences if value.name == "beta"]
    assert len(beta) == 2 and beta[0].purl == beta[1].purl and beta[0].id != beta[1].id
    edge = result.relationships[0]
    child = next(value for value in beta if value.id == edge.child_id)
    assert child.analysis_scope_id == beta[0].analysis_scope_id


def test_missing_descriptor_does_not_fallback_to_equal_name_version(tmp_path):
    write(tmp_path, LEGACY.replace('"beta@^2":', '"beta@~2":'))
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and len(result.occurrences) == 2 and not result.relationships
    assert result.dependency_selectors[0].reason == "yarn-source-endpoint-not-admitted"


def test_overlapping_modern_alias_groups_are_ambiguous(tmp_path):
    content = modern()
    content["beta@npm:^2, beta@npm:~2"] = copy.deepcopy(content["beta@npm:^2"])
    write(tmp_path, content)
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and len(result.occurrences) == 3 and not result.relationships


def test_descriptor_mismatch_does_not_assign_its_selected_version(tmp_path):
    content = modern()
    content["beta@npm:^2"]["version"] = "3.0.0"
    content["beta@npm:^2"]["resolution"] = "beta@npm:3.0.0"
    write(tmp_path, content)
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and not result.relationships
    assert {value.selected_version for value in result.occurrences} == {"1.2.3", "3.0.0"}


def test_private_nonregistry_selector_is_redacted(tmp_path):
    content = modern()
    content["alpha@npm:^1"]["dependencies"]["beta"] = "https://user:secret@example.invalid/a.tgz"
    write(tmp_path, content)
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and not result.relationships
    assert result.dependency_selectors[0].declared_range is None
    assert b"secret" not in canonical_bytes(result)


def test_peer_optional_conditions_remain_unassessed(tmp_path):
    content = modern()
    content["alpha@npm:^1"].pop("dependencies")
    content["alpha@npm:^1"].update(
        peerDependencies={"beta": "npm:^2"}, peerDependenciesMeta={"beta": {"optional": True}}
    )
    write(tmp_path, content)
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and not result.relationships
    assert result.dependency_selectors[0].scopes == ("peer", "optional")
    assert result.dependency_selectors[0].reason == "yarn-peer-context-unassessed"


@pytest.mark.parametrize(
    "content", [LEGACY.replace('  resolved "https://registry.npmjs.org/alpha/-/alpha-1.2.3.tgz"\n', ""), modern()]
)
def test_missing_resolution_remains_fragment(tmp_path, content):
    if type(content) is dict:
        content["alpha@npm:^1"].pop("resolution")
    write(tmp_path, content)
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and len(result.occurrences) == 2
    assert result.coverage.inputs[0].reason == "incomplete-yarn-package-resolution"


def test_cache_checksum_not_relabelled_as_npm_integrity(tmp_path):
    content = modern()
    content["alpha@npm:^1"]["checksum"] = "10c0/" + "a" * 128
    write(tmp_path, content)
    result = run(tmp_path)
    assert result.stages.inventory == "partial"
    assert not any(value.hashes for value in result.occurrences)
    assert result.coverage.inputs[0].reason == "unassessed-yarn-cache-checksum"


@pytest.mark.parametrize("version", ["4", "6", "8", "10"])
def test_known_modern_versions_have_separate_field_admission(tmp_path, version):
    content = modern()
    content["__metadata"]["version"] = version
    write(tmp_path, content)
    assert len(run(tmp_path).occurrences) == 2


@pytest.mark.parametrize("version", ["11", {}, []])
def test_unknown_or_malformed_metadata_has_typed_refusal(tmp_path, version):
    content = modern()
    content["__metadata"]["version"] = version
    write(tmp_path, content)
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and not result.occurrences


def test_global_ledger_refusal_clears_other_languages(tmp_path):
    write(tmp_path, LEGACY)
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    result = run(tmp_path, config=DiscoveryConfig(semantic_checks=100))
    assert result.stages.inventory == "failed" and not result.occurrences and not result.declarations


def test_global_occurrence_limit_clears_other_languages(tmp_path):
    write(tmp_path, LEGACY)
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    result = run(tmp_path, limits=InventoryLimits(occurrences=2))
    assert result.stages.inventory == "failed" and not result.occurrences and not result.declarations


def test_final_source_epoch_still_required(tmp_path, monkeypatch):
    write(tmp_path, LEGACY)

    def changed(self):
        raise InputRefusal("changed-source-input")

    monkeypatch.setattr(Source, "validate", changed)
    result = run(tmp_path)
    assert result.stages.inventory == "failed" and not result.occurrences and not result.relationships


def test_refused_overlapping_entry_still_blocks_descriptor_endpoint(tmp_path):
    content = modern()
    content["beta@npm:^2, beta@npm:~2"] = {"version": "not-a-version"}
    write(tmp_path, content)
    result = run(tmp_path)
    assert len(result.occurrences) == 2 and not result.relationships
    assert result.dependency_selectors[0].disposition == "unresolved"
    assert result.coverage.inputs[0].reason == "ambiguous-yarn-source-descriptor"


def test_legacy_utf8_bom_preserves_format_detection(tmp_path):
    write(tmp_path, "\ufeff" + LEGACY)
    result = run(tmp_path)
    assert len(result.occurrences) == 2 and len(result.relationships) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", []),
        ("resolution", {}),
        ("linkType", []),
        ("dependencies", []),
        ("dependenciesMeta", {"beta": []}),
        ("dependenciesMeta", {"beta": {"optional": []}}),
        ("languageName", {}),
    ],
)
def test_malformed_package_controls_remain_file_local(tmp_path, field, value):
    content = modern()
    content["alpha@npm:^1"][field] = value
    write(tmp_path, content)
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    result = run(tmp_path)
    assert result.stages.inventory == "partial"
    assert "pip" in {value.name for value in result.occurrences}


def test_invalid_modern_unicode_refuses_file_before_hashing(tmp_path):
    (tmp_path / "yarn.lock").write_text(
        '__metadata: {version: "10"}\n"alpha@npm:^1": {version: "1.0.0", resolution: "alpha@npm:1.0.0", conditions: "\\uD800"}\n'
    )
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and [value.name for value in result.occurrences] == ["pip"]
    assert (
        next(value for value in result.coverage.inputs if value.format == "yarn-lock").reason == "invalid-yaml-unicode"
    )


@pytest.mark.parametrize("key,reference", [("beta@^2", "^2"), ("beta@npm:^2", "^2"), ("beta@^2", "npm:^2")])
def test_modern_missing_protocol_never_infers_registry_descriptor(tmp_path, key, reference):
    content = modern()
    beta = content.pop("beta@npm:^2")
    content[key] = beta
    content["alpha@npm:^1"]["dependencies"]["beta"] = reference
    write(tmp_path, content)
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and not result.relationships
    assert all(value.name != "beta" for value in result.occurrences) if key == "beta@^2" else True


def test_classic_npm_alias_cannot_promote_declared_alias_to_actual_package(tmp_path):
    write(
        tmp_path,
        '# yarn lockfile v1\n"alpha@npm:beta@^2":\n  version "2.0.0"\n  resolved "https://registry.npmjs.org/beta/-/beta-2.0.0.tgz"\n',
    )
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and not result.occurrences


def test_classic_alias_group_can_retain_identity_from_valid_same_name_descriptor(tmp_path):
    write(tmp_path, LEGACY.replace('"alpha@^1":', '"alpha@^1", "alpha@https://user:secret@example.invalid/a.tgz":'))
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and {value.name for value in result.occurrences} == {"alpha", "beta"}
    assert b"secret" not in canonical_bytes(result)


def test_modern_bare_peer_range_retained_without_endpoint_inference(tmp_path):
    content = modern()
    content["alpha@npm:^1"].pop("dependencies")
    content["alpha@npm:^1"]["peerDependencies"] = {"beta": ">= 1 < 3"}
    write(tmp_path, content)
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and len(result.occurrences) == 2 and not result.relationships
    (selector,) = result.dependency_selectors
    assert selector.declared_range == ">= 1 < 3" and selector.child_id is None
    assert selector.scopes == ("peer",) and selector.reason == "yarn-peer-context-unassessed"
