"""Source identities, nested endpoints and conditions, without npm execution."""

import base64
import hashlib
import json
import time

import pytest

from sourcebastion.inventory.compose_source import compose_source
from sourcebastion.inventory.contract import Inventory, InventoryLimits, Producer, canonical_bytes
from sourcebastion.inventory.inputs import Source, InputRefusal
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256
from sourcebastion.inventory import npm_sources

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


def write(root, files):
    for path, data in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(data if type(data) is str else json.dumps(data))


def lock(packages, **extra):
    return {"lockfileVersion": 3, "packages": packages, **extra}


def complete():
    return {
        "package.json": {"name": "fixture", "version": "1.0.0", "dependencies": {"debug": "^4.3.7"}},
        "package-lock.json": lock(
            {
                "": {"name": "fixture", "version": "1.0.0", "dependencies": {"debug": "^4.3.7"}},
                "node_modules/debug": {"version": "4.3.7", "dependencies": {"ms": "^2.1.3"}},
                "node_modules/ms": {"version": "2.1.3"},
            }
        ),
    }


def test_explicit_paired_application_and_lock_edges(tmp_path):
    write(tmp_path, complete())
    result = run(tmp_path)
    assert result.stages.inventory == "partial"  # manifest range is not an install selection
    assert len(result.applications) == len(result.roots) == 1
    assert result.applications[0].name == "fixture"
    locked = {r.name: r for r in result.occurrences if r.evidence_kind == "locked"}
    assert locked["debug"].directness == "direct" and locked["ms"].directness == "transitive"
    assert locked["debug"].root_id == locked["ms"].root_id == result.roots[0].id
    assert result.occurrences[0].selected_version is None  # no sibling lock pin borrowed
    assert result.dependency_selectors[0].dialect == "npm-semver-7.8.5"
    edge = result.relationships[0]
    assert (edge.parent_id, edge.child_id) == (locked["debug"].id, locked["ms"].id)
    assert edge.source.locator == "/packages/node_modules~1debug/dependencies/ms"
    assert result.coverage.graph == "partial" and not result.installed_environments
    assert all(r.activation == "unknown" and r.installed_environment_id is None for r in result.occurrences)
    assert canonical_bytes(result) == canonical_bytes(run(tmp_path))


def test_same_name_nested_versions_select_nearest_path_not_name(tmp_path):
    write(
        tmp_path,
        {
            "package-lock.json": lock(
                {
                    "node_modules/debug": {"version": "4.3.7", "dependencies": {"ms": "2.0.0"}},
                    "node_modules/ms": {"version": "2.1.3"},
                    "node_modules/debug/node_modules/ms": {"version": "2.0.0"},
                }
            )
        },
    )
    result = run(tmp_path)
    assert result.stages.inventory == "complete" and len(result.occurrences) == 3
    child = next(row for row in result.occurrences if row.id == result.relationships[0].child_id)
    assert child.selected_version == "2.0.0" and child.source.locator.endswith("node_modules~1debug~1node_modules~1ms")
    assert all(row.root_id is None and row.directness == "unknown" for row in result.occurrences)


def test_present_refused_nearer_entry_blocks_ancestor_fallback(tmp_path):
    write(
        tmp_path,
        {
            "package-lock.json": lock(
                {
                    "node_modules/debug": {"version": "4.3.7", "dependencies": {"ms": "^2"}},
                    "node_modules/ms": {"version": "2.1.3"},
                    "node_modules/debug/node_modules/ms": {"link": True, "resolved": "../fake"},
                }
            )
        },
    )
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and len(result.occurrences) == 2
    assert not result.relationships and result.dependency_selectors[0].child_id is None
    assert result.dependency_selectors[0].reason == "npm-source-endpoint-not-admitted"


@pytest.mark.parametrize(
    "selector,version,reason",
    [
        ("^3", "2.1.3", "npm-selector-version-mismatch"),
        ("^2", "2.2.0-beta.1", "npm-selector-version-mismatch"),
        ("npm:other@^2", "2.1.3", "unsupported-npm-dependency-selector"),
        ("https://example.invalid/x.tgz", "2.1.3", "unsupported-npm-dependency-selector"),
    ],
)
def test_incompatible_protocol_or_prerelease_selector_stays_unresolved(tmp_path, selector, version, reason):
    write(
        tmp_path,
        {
            "package-lock.json": lock(
                {
                    "node_modules/debug": {"version": "4.3.7", "dependencies": {"ms": selector}},
                    "node_modules/ms": {"version": version},
                }
            )
        },
    )
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and not result.relationships
    assert result.dependency_selectors[0].reason == reason


def test_optional_override_peer_and_dev_scope_remain_distinct(tmp_path):
    write(
        tmp_path,
        {
            "package.json": {
                "name": "fixture",
                "version": "1.0.0",
                "dependencies": {"ms": "^1"},
                "optionalDependencies": {"ms": "2.1.3"},
                "devDependencies": {"ms": "2.0.0"},
                "peerDependencies": {"ms": "^2"},
                "peerDependenciesMeta": {"ms": {"optional": True}},
            },
            "package-lock.json": lock(
                {
                    "node_modules/debug": {
                        "version": "4.3.7",
                        "optional": True,
                        "peerDependencies": {"ms": "^2"},
                        "dependencies": {"ms": "^2"},
                    },
                    "node_modules/ms": {"version": "2.1.3", "dev": True},
                }
            ),
        },
    )
    result = run(tmp_path)
    declared = [row for row in result.occurrences if row.evidence_kind == "declared"]
    assert {row.scopes for row in declared} == {("optional",), ("development",), ("peer", "optional")}
    assert len(result.relationships) == 1 and result.relationships[0].scopes == ("runtime",)
    peer = next(row for row in result.dependency_selectors if row.scopes == ("peer",))
    assert peer.disposition == "unresolved" and peer.reason == "npm-peer-context-unassessed"
    assert all(row.activation == "unknown" for row in result.occurrences)


def test_lock_integrity_source_hash_and_scoped_package_identity(tmp_path):
    integrity = "sha512-" + base64.b64encode(bytes(range(64))).decode()
    uri = "https://user:private@registry.invalid/scope/pkg.tgz?secret=private"
    write(
        tmp_path,
        {
            "npm-shrinkwrap.json": lock(
                {"node_modules/@scope/pkg": {"version": "1.2.3+build.4", "integrity": integrity, "resolved": uri}}
            )
        },
    )
    result = run(tmp_path)
    row = result.occurrences[0]
    assert row.purl == "pkg:npm/%40scope/pkg@1.2.3%2Bbuild.4"
    assert row.hashes[0].digest == bytes(range(64)).hex() and row.hashes[0].kind == "integrity"
    assert row.registry_source_sha256 == hashlib.sha256(uri.encode()).hexdigest()
    assert b"private" not in canonical_bytes(result) and b"registry.invalid" not in canonical_bytes(result)


@pytest.mark.parametrize(
    "fields",
    [
        {"version": "file:../other"},
        {"version": "1.0.0", "resolved": "git+https://example.invalid/repo"},
        {"version": "1.0.0", "name": "different"},
        {"version": "1.0.0", "integrity": "sha512-invalid"},
        {"version": "1.0.0", "link": True},
        {"version": "9007199254740992.0.0"},
    ],
)
def test_unproved_identity_entries_omit_without_promoting_other_entries(tmp_path, fields):
    write(
        tmp_path, {"package-lock.json": lock({"node_modules/bad": fields, "node_modules/good": {"version": "1.0.0"}})}
    )
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and {row.name for row in result.occurrences} == {"good"}


@pytest.mark.parametrize(
    "text,reason",
    [
        ('{"dependencies":{"x":"1.0.0","x":"2.0.0"}}', "duplicate-npm-source-key"),
        ('{"dependencies":', "invalid-npm-source-syntax"),
        ('{"dependencies":[]}', "invalid-npm-source-table"),
        ('{"dependencies":{"x":"bad\\u007f"}}', "invalid-npm-source-text"),
    ],
)
def test_malformed_source_has_fixed_private_diagnostic(tmp_path, text, reason):
    write(tmp_path, {"package.json": text})
    result = run(tmp_path)
    assert not result.occurrences and result.coverage.inputs[0].reason == reason
    assert b"bad" not in canonical_bytes(result)


@pytest.mark.parametrize(
    "key", ["workspaces", "overrides", "resolutions", "engines", "os", "cpu", "libc", "bundledDependencies"]
)
def test_selection_controls_preserve_partial_coverage_without_project_execution(tmp_path, key):
    write(
        tmp_path,
        {
            "package.json": {
                "name": "fixture",
                "version": "1.0.0",
                "dependencies": {"ms": "2.1.3"},
                key: [],
                "scripts": {"preinstall": "touch EXECUTED"},
            }
        },
    )
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and result.occurrences[0].selected_version == "2.1.3"
    assert (
        result.coverage.inputs[0].reason == "unsupported-npm-selection-controls"
        and not (tmp_path / "EXECUTED").exists()
    )


@pytest.mark.parametrize("change", [{"name": "other"}, {"version": "2.0.0"}, {"dependencies": {"debug": "^5"}}])
def test_same_folder_or_application_name_does_not_override_conflicting_pair(tmp_path, change):
    data = complete()
    data["package.json"].update(change)
    write(tmp_path, data)
    result = run(tmp_path)
    assert len(result.applications) == len(result.roots) == 2
    assert {row.root_id for row in result.occurrences if row.evidence_kind == "locked"}.isdisjoint(
        {row.root_id for row in result.occurrences if row.evidence_kind == "declared"}
    )


def test_one_discovery_and_global_budget_refusal_clears_graph(tmp_path, monkeypatch):
    import sourcebastion.inventory.compose_requirements as composer

    original, calls = composer.discover, []

    def counted(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(composer, "discover", counted)
    write(tmp_path, complete())
    result = run(tmp_path, limits=InventoryLimits(occurrences=1))
    assert calls == [1] and result.stages.inventory == "failed" and not result.occurrences and not result.relationships
    result = run(tmp_path, config=DiscoveryConfig(semantic_checks=100))
    assert (
        result.stages.inventory == "failed"
        and result.occurrences == result.declarations == result.dependency_selectors == ()
    )


def test_final_epoch_failure_clears_mixed_python_and_npm_evidence(tmp_path, monkeypatch):
    from sourcebastion.inventory import npm_selectors

    original = npm_selectors.evaluate
    write(tmp_path, {**complete(), "requirements.txt": "pip==26.0.1"})

    def changed(*args, **kwargs):
        answers = original(*args, **kwargs)
        (tmp_path / "package-lock.json").write_text("{}")
        return answers

    monkeypatch.setattr(npm_selectors, "evaluate", changed)
    result = run(tmp_path)
    assert (
        result.stages.inventory == "failed"
        and result.occurrences
        == result.declarations
        == result.relationships
        == result.roots
        == result.applications
        == ()
    )


def test_depth_bounded_before_json_decoder_and_record_limit_before_semver(tmp_path, monkeypatch):
    data = '{"ignored":' + "[" * 33 + "0" + "]" * 33 + "}"
    write(tmp_path, {"package.json": data})
    result = run(tmp_path)
    assert result.stages.inventory == "failed" and result.coverage.refusal_codes == (
        "npm-source-depth-budget-exceeded",
    )
    document = npm_sources.parse(
        json.dumps({"dependencies": {"a": "1", "b": "2"}}).encode(),
        "npm-manifest",
        deadline=time.monotonic() + 10,
        check=lambda: None,
        max_records=1,
    )
    assert document.disposition == "bounded-omission" and not document.declarations


def test_structural_selector_ecosystem_cannot_be_relabelled(tmp_path):
    write(
        tmp_path,
        {
            "package-lock.json": lock(
                {
                    "node_modules/debug": {"version": "4.3.7", "dependencies": {"ms": "^2"}},
                    "node_modules/ms": {"version": "2.1.3"},
                }
            )
        },
    )
    result = run(tmp_path)
    selector = result.dependency_selectors[0]
    for update in (
        {"dialect": "pep440"},
        {"marker": 'sys_platform == "linux"'},
        {"activation": "active"},
        {"extras": ("feature",)},
    ):
        with pytest.raises(ValueError):
            Inventory.model_validate(
                result.model_copy(update={"dependency_selectors": (selector.model_copy(update=update),)})
            )


@pytest.mark.parametrize("present", [False, True])
@pytest.mark.parametrize("kind", ["manifest", "lock-root", "lock-edge"])
def test_unsupported_selector_credentials_remain_private_for_all_endpoint_states(tmp_path, present, kind):
    secret = "https://alice:secret-token@example.invalid/a.tgz"
    packages = {"node_modules/foo": {"version": "1.0.0", "dependencies": {"bar": secret}}}
    if present:
        packages["node_modules/bar"] = {"version": "1.0.0"}
    if kind == "manifest":
        data = {"package.json": {"dependencies": {"bar": secret}}}
    else:
        if kind == "lock-root":
            packages[""] = {"name": "fixture", "version": "1.0.0", "dependencies": {"bar": secret}}
            packages["node_modules/foo"].pop("dependencies")
        data = {"package-lock.json": lock(packages)}
    write(tmp_path, data)
    result = run(tmp_path)
    assert result.stages.inventory == "partial"
    assert b"secret-token" not in canonical_bytes(result) and b"alice" not in canonical_bytes(result)
    assert all(row.declared_range is None for row in (*result.declarations, *result.dependency_selectors))
    assert all(row.source.source_sha256 for row in (*result.declarations, *result.dependency_selectors))
    assert not result.relationships
    if kind == "lock-edge":
        assert result.dependency_selectors[0].reason == "unsupported-npm-dependency-selector"


@pytest.mark.parametrize("flag,scope", [("peer", ("peer",)), ("extraneous", ("unknown",))])
def test_unproved_lock_context_flags_are_not_runtime_or_complete(tmp_path, flag, scope):
    write(tmp_path, {"package-lock.json": lock({"node_modules/foo": {"version": "1.0.0", flag: True}})})
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and result.occurrences[0].scopes == scope
    assert result.coverage.inputs[0].reason == "unsupported-npm-package-selection-context"
    assert result.occurrences[0].activation == "unknown"


@pytest.mark.parametrize("flag", ["peer", "extraneous"])
def test_malformed_lock_context_flag_is_not_coerced(tmp_path, flag):
    write(tmp_path, {"package-lock.json": lock({"node_modules/foo": {"version": "1.0.0", flag: "false"}})})
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and not result.occurrences
    assert result.coverage.inputs[0].reason == "invalid-npm-package-flag"


@pytest.mark.parametrize("key", ["pnpm", "dependenciesMeta", "installConfig", "acceptDependencies"])
def test_additional_manager_selection_controls_are_not_silently_complete(tmp_path, key):
    write(
        tmp_path,
        {
            "package.json": {
                "name": "fixture",
                "version": "1.0.0",
                "dependencies": {"foo": "1.0.0"},
                key: {"foo": "2.0.0"},
            }
        },
    )
    result = run(tmp_path)
    assert (
        result.stages.inventory == "partial"
        and result.coverage.inputs[0].reason == "unsupported-npm-selection-controls"
    )


def test_absent_root_endpoint_does_not_invent_dummy_direct_occurrence(tmp_path):
    write(
        tmp_path,
        {
            "package-lock.json": lock(
                {"": {"dependencies": {"missing": "*"}}, "node_modules/other": {"version": "1.0.0"}}
            )
        },
    )
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and result.occurrences[0].directness == "unknown"
    assert result.occurrences[0].root_id is None and not result.relationships


@pytest.mark.parametrize("fmt", ["manifest", "lock"])
def test_npm_application_version_uses_maintained_strict_grammar(tmp_path, fmt):
    application = {"name": "fixture", "version": "9007199254740992.0.0", "dependencies": {"foo": "1.0.0"}}
    data = (
        {"package.json": application}
        if fmt == "manifest"
        else {"package-lock.json": lock({"": application, "node_modules/foo": {"version": "1.0.0"}})}
    )
    write(tmp_path, data)
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and not result.roots and not result.applications
    assert result.occurrences[0].name == "foo" and result.occurrences[0].selected_version == "1.0.0"
    assert result.occurrences[0].root_id is None
    assert result.coverage.inputs[0].reason == "unsupported-npm-application-version"
