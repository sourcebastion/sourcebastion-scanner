#!/usr/bin/env python3
"""Finite installed Python source composition checks plus 64-case repeatability records.

No production scanner route, rich corpus acceptance, matching or kernel proof.
"""

import hashlib
import json
from pathlib import Path
import platform
import signal
import sys
import tempfile

import packaging
import packaging.markers
import pydantic
import yaml

from sourcebastion.inventory import (
    compose_requirements,
    compose_source,
    compose_manifests,
    compose_locks,
    compose_npm,
    compose_pnpm,
    compose_yarn,
    yarn_sources,
    yarn_legacy,
    pnpm_sources,
    bounded_yaml,
    npm_sources,
    npm_selectors,
    python_locks,
    python_lock_formats,
    poetry_constraints,
    contract,
    discovery,
    inputs,
    markers,
    python_manifests,
    registry,
    requirements,
)


def compose(root, files, *, links=None, environment=None, config=None):
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    for name, target in (links or {}).items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)
    config = config or registry.DiscoveryConfig()
    # Identity of this synthetic controller's declared fixture, not a claim
    # that recognized files establish a complete arbitrary checkout digest.
    sha = hashlib.sha256(json.dumps([files, links or {}], sort_keys=True).encode()).hexdigest()
    with inputs.Source(root) as source:
        return compose_source.compose_source(
            source,
            source_sha256=sha,
            producer=contract.Producer(
                name="native-synthetic-composition-probe",
                version="1",
                code_sha256="a" * 64,
                registry_sha256=registry.REGISTRY_SHA256,
                config_sha256=config.sha256,
            ),
            config=config,
            environment=environment,
        )


def record_case(name, files, *, links=None, environment=None, config=None):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        first = compose(root, files, links=links, environment=environment, config=config)
        encoded = contract.canonical_bytes(first)
        assert contract.canonical_bytes(contract.Inventory.model_validate_json(encoded)) == encoded
        # Use a new Source and fresh directory; repeat does not reuse its cache.
    with tempfile.TemporaryDirectory() as directory:
        repeated = compose(Path(directory), files, links=links, environment=environment, config=config)
        assert encoded == contract.canonical_bytes(repeated)
    return first, {
        "id": name,
        "inventory_status": first.stages.inventory,
        "occurrences": len(first.occurrences),
        "declarations": len(first.declarations),
        "references": len(first.input_references),
        "canonical_sha256": hashlib.sha256(encoded).hexdigest(),
        "refusal_codes": first.coverage.refusal_codes,
    }


def main():
    if sys.flags.optimize:
        raise RuntimeError("optimized-probe-runtime-refused")
    signal.alarm(60)
    assert packaging.__version__ == "26.3"
    assert poetry_constraints.GRAMMAR_VERSION == "2.1.3"
    modules = (
        compose_requirements,
        compose_source,
        compose_manifests,
        compose_locks,
        compose_npm,
        compose_pnpm,
        compose_yarn,
        yarn_sources,
        yarn_legacy,
        pnpm_sources,
        bounded_yaml,
        npm_sources,
        npm_selectors,
        python_locks,
        python_lock_formats,
        poetry_constraints,
        contract,
        discovery,
        inputs,
        markers,
        python_manifests,
        registry,
        requirements,
    )
    for module in modules:
        assert "/site-packages/sourcebastion/inventory/" in module.__file__

    def no_host(*_args, **_kwargs):
        raise AssertionError("host-marker-input-not-authorized")

    packaging.markers.default_environment = no_host
    packaging.markers.Marker.evaluate = no_host
    semantic = []
    flat, record = record_case("flat-source-pin", {"requirements.txt": "Pip==v26.0.1\n"})
    assert flat.stages.inventory == "complete" and len(flat.occurrences) == 1
    row = flat.occurrences[0]
    assert row.name == "pip" and row.selected_version == "26.0.1" and row.declared_range == "==v26.0.1"
    assert row.root_id is row.installed_environment_id is None and row.selection_declaration_ids
    assert not flat.roots and not flat.relationships and not flat.applications
    semantic.append(record)

    shared, record = record_case(
        "shared-origin-constraints",
        {
            "a/requirements.txt": "-r ../shared.in\n-c selected.in\n",
            "a/selected.in": "pip==26.0.1\nunused==99\n",
            "b/requirements.txt": "-r ../shared.in\n-c selected.in\n",
            "b/selected.in": "pip==26.2\n",
            "shared.in": "pip>=26\n",
        },
    )
    assert shared.stages.inventory == "complete" and len(shared.analysis_scopes) == 2
    assert {p.selected_version for p in shared.occurrences} == {"26.0.1", "26.2"}
    assert {p.name for p in shared.occurrences} == {"pip"} and len(shared.input_references) == 4
    declarations = {d.id: d for d in shared.declarations}
    for occurrence in shared.occurrences:
        evidence = [declarations[key] for key in occurrence.selection_declaration_ids]
        assert {d.kind for d in evidence} == {"requirement", "constraint"}
        assert {d.analysis_scope_id for d in evidence} == {occurrence.analysis_scope_id}
    semantic.append(record)

    for name, files, reason in (
        (
            "conflict",
            {"requirements.txt": "pip==26.0.1\n-c constraints.txt\n", "constraints.txt": "pip>=27\n"},
            "constraint-conflict",
        ),
        ("refused-parent", {"requirements.txt": "-r child.in\n--unknown-option\n", "child.in": "pip==26.0.1\n"}, None),
        (
            "cyclic-origin",
            {
                "z.in": "-r y.in\n-r a.in\n",
                "y.in": "-r z.in\n",
                "a.in": "pip==26.0.1\n",
                "independent.in": "setuptools==80.0\n",
            },
            "include-cycle",
        ),
    ):
        result, record = record_case(name, files)
        assert result.stages.inventory == "partial"
        assert not any(p.selected_version for p in result.occurrences if p.name == "pip")
        if reason:
            assert reason in result.coverage.refusal_codes
        if name == "cyclic-origin":
            assert {p.name for p in result.occurrences if p.selected_version is not None} == {"setuptools"}
        semantic.append(record)

    limited, record = record_case(
        "shared-semantic-budget",
        {
            "requirements.txt": "pip>=26\n-r shared.in\n-c shared.in\n",
            "shared.in": "-c constraints.in\n",
            "constraints.in": "pip==26.0.1\n",
        },
        config=registry.DiscoveryConfig(semantic_checks=73),
    )
    assert limited.stages.inventory == "failed"
    assert limited.occurrences == limited.declarations == limited.input_references == ()
    assert "composition-check-budget-exceeded" in limited.coverage.refusal_codes
    semantic.append(record)

    expanded, record = record_case(
        "repeated-selection-work-budget",
        {
            "requirements.txt": "pip>=0\n" * 50 + "-c constraints.in\n",
            "constraints.in": "pip==1\n" + "".join("pip>=0." + str(n) + "\n" for n in range(1, 100)),
        },
        config=registry.DiscoveryConfig(semantic_checks=1131),
    )
    assert expanded.stages.inventory == "failed"
    assert expanded.occurrences == expanded.declarations == expanded.input_references == ()
    assert "composition-check-budget-exceeded" in expanded.coverage.refusal_codes
    semantic.append(record)

    alternatives = {"requirements.txt": 'pip==26.0.1; python_version < "3.13"\npip==26.2; python_version >= "3.13"\n'}
    unknown, record = record_case("marker-alternatives", alternatives)
    assert {p.activation for p in unknown.occurrences} == {"unknown"}
    assert {p.selected_version for p in unknown.occurrences} == {"26.0.1", "26.2"}
    semantic.append(record)
    target, record = record_case(
        "explicit-target",
        alternatives,
        environment=contract.Environment(policy="explicit-target", python_version="3.12.9"),
    )
    assert {p.selected_version: p.activation for p in target.occurrences} == {"26.0.1": "active", "26.2": "inactive"}
    semantic.append(record)

    with tempfile.TemporaryDirectory() as directory:
        original = inputs.Source.validate
        calls = 0
        root = Path(directory)

        def change_at_final(source):
            nonlocal calls
            calls += 1
            if calls == 2:
                (root / "requirements.txt").write_text("pip==26.2\n")
            original(source)

        inputs.Source.validate = change_at_final
        try:
            failed = compose(root, {"requirements.txt": "pip==26.0.1\n"})
        finally:
            inputs.Source.validate = original
        assert calls == 2 and failed.stages.inventory == "failed"
        assert failed.occurrences == failed.declarations == failed.input_references == failed.analysis_scopes == ()
        assert any(code.startswith("changed-") for code in failed.coverage.refusal_codes)

    manifest, record = record_case(
        "static-project-conditions",
        {
            "pyproject.toml": '[project]\nname="native-app"\nversion="v1.0"\nrequires-python=">=3.12,<3.13"\ndependencies=["pip==26.0.1"]\n[project.optional-dependencies]\ntest=["pytest==8.3.3; sys_platform == \\"linux\\""]\n[build-system]\nrequires=["setuptools==80.0"]\n'
        },
    )
    assert manifest.stages.inventory == "complete"
    assert len(manifest.roots) == len(manifest.applications) == 1
    assert manifest.applications[0].name == "native-app" and manifest.applications[0].version == "1.0"
    assert {p.name: p.activation for p in manifest.occurrences} == {
        "pip": "unknown",
        "pytest": "unknown",
        "setuptools": "active",
    }
    assert {a.kind for a in manifest.applicability} == {"python-version", "group"}
    assert not manifest.relationships and not manifest.installed_environments
    semantic.append(record)
    manifest_target, record = record_case(
        "static-project-explicit-target",
        {
            "pyproject.toml": '[project]\nname="native-app"\nversion="v1.0"\nrequires-python=">=3.12,<3.13"\ndependencies=["pip==26.0.1"]\n[project.optional-dependencies]\ntest=["pytest==8.3.3; sys_platform == \\"linux\\""]\n[build-system]\nrequires=["setuptools==80.0"]\n'
        },
        environment=contract.Environment(policy="explicit-target", python_version="3.13.1", platform="linux"),
    )
    assert {p.name: p.activation for p in manifest_target.occurrences} == {
        "pip": "inactive",
        "pytest": "inactive",
        "setuptools": "active",
    }
    semantic.append(record)
    combined, record = record_case(
        "requirements-and-project",
        {
            "requirements.txt": "pip==26.0.1\n",
            "pyproject.toml": '[project]\nname="native-app"\nversion="1"\ndependencies=["pip==26.0.1"]\n',
        },
    )
    assert combined.stages.inventory == "complete" and len(combined.occurrences) == 2
    assert {p.root_id for p in combined.occurrences} == {None, combined.roots[0].id}
    semantic.append(record)

    build, record = record_case(
        "project-target-is-not-build-target",
        {
            "pyproject.toml": '[project]\nname="native-build"\nversion="1"\nrequires-python=">=3.13"\n[build-system]\nrequires=["setuptools==80.0; python_version < \\"3.13\\"", "wheel==0.45.1; sys_platform == \\"linux\\""]\n'
        },
        environment=contract.Environment(policy="explicit-target", python_version="3.13.1", platform="linux"),
    )
    assert len(build.occurrences) == 2 and {p.activation for p in build.occurrences} == {"unknown"}
    assert all(p.scopes == ("build",) for p in build.occurrences)
    semantic.append(record)

    lock_sha = "a" * 64
    poetry_header = '[metadata]\nlock-version="2.1"\npython-versions=">=3.12"\ncontent-hash="' + lock_sha + '"\n'
    pdm_header = (
        '[metadata]\nlock_version="4.5.0"\ngroups=["default","test"]\nstrategy=["inherit_metadata"]\ncontent_hash="sha256:'
        + lock_sha
        + '"\n'
    )
    uv_header = 'version=1\nrevision=3\nrequires-python=">=3.12"\n'

    def lock_package(name="foo", style="poetry", extra=""):
        header = '[[package]]\nname="' + name + '"\nversion="1"\n'
        fields = {
            "poetry": 'optional=false\npython-versions=">=3.12"\ngroups=["main"]\n',
            "pdm": 'requires_python=">=3.12"\ngroups=["default"]\n',
            "uv": 'source={registry="https://pypi.org/simple"}\n',
        }
        artifact = (
            'wheels=[{url="https://packages.invalid/' + name + '-1-py3-none-any.whl",hash="sha256:' + lock_sha + '"}]\n'
            if style == "uv"
            else 'files=[{file="' + name + '-1-py3-none-any.whl",hash="sha256:' + lock_sha + '"}]\n'
        )
        return header + fields[style] + artifact + extra

    for style, header in (("poetry", poetry_header), ("pdm", pdm_header), ("uv", uv_header)):
        result, record = record_case("locked-" + style, {style + ".lock": header + lock_package(style=style)})
        assert result.stages.inventory == "complete" and len(result.occurrences) == 1
        occurrence = result.occurrences[0]
        assert occurrence.evidence_kind == "locked" and occurrence.selected_version == "1"
        assert occurrence.root_id is occurrence.installed_environment_id is None
        assert occurrence.activation == "unknown" and occurrence.hashes[0].digest == lock_sha
        assert not result.roots and not result.applications
        semantic.append(record)
    pipfile = json.dumps(
        {
            "_meta": {"pipfile-spec": 6, "hash": {"sha256": lock_sha}, "requires": {}, "sources": []},
            "default": {"foo": {"version": "==1", "hashes": ["sha256:" + lock_sha]}},
        }
    )
    result, record = record_case("locked-pipfile", {"Pipfile.lock": pipfile})
    assert result.stages.inventory == "complete" and result.occurrences[0].evidence_kind == "locked"
    assert result.occurrences[0].hashes[0].digest == lock_sha
    semantic.append(record)
    pylock = (
        'lock-version="1.0"\ncreated-by="native"\n[[packages]]\nname="foo"\nversion="1"\n'
        'wheels=[{name="foo-1-py3-none-any.whl",url="https://packages.invalid/foo.whl",hashes={sha256="'
        + lock_sha
        + '"}}]\n'
    )
    result, record = record_case("locked-pylock", {"pylock.toml": pylock})
    assert result.stages.inventory == "complete" and result.occurrences[0].evidence_kind == "locked"
    semantic.append(record)
    result, record = record_case(
        "poetry-conditional-graph",
        {
            "poetry.lock": poetry_header
            + lock_package("parent", extra='[package.dependencies]\nfoo="^1.0"\n')
            + lock_package()
        },
    )
    assert result.stages.inventory == "complete" and len(result.relationships) == len(result.dependency_selectors) == 1
    selector = result.dependency_selectors[0]
    assert (
        selector.declared_range == "^1.0"
        and selector.dialect == "poetry-core-2.1.3"
        and selector.activation == "unknown"
    )
    assert result.relationships[0].selector_id == selector.id and result.coverage.graph == "partial"
    semantic.append(record)
    result, record = record_case(
        "pdm-multigroup-graph",
        {
            "pdm.lock": pdm_header
            + (lock_package("parent", "pdm", 'dependencies=["foo>=1"]\n') + lock_package(style="pdm")).replace(
                'groups=["default"]', 'groups=["default","test"]'
            )
        },
    )
    assert result.stages.inventory == "complete" and len(result.occurrences) == 4 and len(result.relationships) == 2
    assert {selector.groups for selector in result.dependency_selectors} == {("default",), ("test",)}
    semantic.append(record)
    uv_parent = lock_package("parent", "uv", 'dependencies=[{name="foo",version="1"}]\n')
    result, record = record_case(
        "uv-ambiguous-source",
        {
            "uv.lock": uv_header
            + uv_parent
            + lock_package(style="uv")
            + lock_package(style="uv").replace("pypi.org", "other.invalid")
        },
    )
    assert result.stages.inventory == "partial" and not result.relationships and len(result.dependency_selectors) == 1
    assert (
        result.dependency_selectors[0].child_id is None
        and result.dependency_selectors[0].reason == "ambiguous-lock-dependency"
    )
    semantic.append(record)
    result, record = record_case(
        "uv-relative-marker",
        {
            "uv.lock": uv_header
            + lock_package("parent", "uv", 'dependencies=[{name="foo",marker="python_version < \'3.14\'"}]\n')
            + lock_package(style="uv")
        },
        environment=contract.Environment(policy="explicit-target", python_version="3.15.1"),
    )
    assert (
        result.stages.inventory == "complete"
        and result.dependency_selectors[0].marker_semantics == "relative-to-lock-python"
    )
    assert result.dependency_selectors[0].activation == result.relationships[0].activation == "unknown"
    semantic.append(record)
    result, record = record_case("missing-lock-target", {"uv.lock": uv_header + uv_parent})
    assert (
        result.stages.inventory == "partial"
        and not result.relationships
        and result.dependency_selectors[0].reason == "missing-lock-dependency"
    )
    semantic.append(record)
    result, record = record_case(
        "lock-shared-budget",
        {"uv.lock": uv_header + lock_package(style="uv"), "requirements.txt": "pip==26.0.1\n"},
        config=registry.DiscoveryConfig(semantic_checks=20),
    )
    assert (
        result.stages.inventory == "failed"
        and not result.occurrences
        and not result.relationships
        and not result.dependency_selectors
    )
    semantic.append(record)

    npm_lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "fixture", "version": "1.0.0", "dependencies": {"debug": "^4.3.7"}},
            "node_modules/debug": {"version": "4.3.7", "dependencies": {"ms": "^2.0.0"}},
            "node_modules/ms": {"version": "2.1.3"},
            "node_modules/debug/node_modules/ms": {"version": "2.0.0"},
        },
    }
    result, record = record_case("npm-nested-source-selection", {"package-lock.json": json.dumps(npm_lock)})
    assert result.stages.inventory == "complete" and len(result.occurrences) == 3
    assert len(result.relationships) == len(result.dependency_selectors) == 1
    by_id = {row.id: row for row in result.occurrences}
    edge = result.relationships[0]
    assert by_id[edge.parent_id].directness == "direct" and by_id[edge.child_id].directness == "transitive"
    assert by_id[edge.child_id].selected_version == "2.0.0"
    assert result.dependency_selectors[0].dialect == "npm-semver-7.8.5"
    assert all(row.activation == "unknown" and row.installed_environment_id is None for row in result.occurrences)
    semantic.append(record)
    for name, change, reason in (
        ("npm-nearer-refused", {"link": True, "resolved": "../other"}, "npm-source-endpoint-not-admitted"),
        ("npm-range-mismatch", {"version": "3.0.0"}, "npm-selector-version-mismatch"),
        ("npm-prerelease-policy", {"version": "2.2.0-beta.1"}, "npm-selector-version-mismatch"),
    ):
        changed = json.loads(json.dumps(npm_lock))
        changed["packages"]["node_modules/debug/node_modules/ms"] = change
        result, record = record_case(name, {"package-lock.json": json.dumps(changed)})
        assert result.stages.inventory == "partial" and not result.relationships
        assert result.dependency_selectors[0].reason == reason
        semantic.append(record)
    manifest = {
        "name": "fixture",
        "version": "1.0.0",
        "dependencies": {"debug": "^4.3.7"},
        "scripts": {"preinstall": "touch EXECUTED"},
    }
    result, record = record_case("npm-declared-range-no-resolver", {"package.json": json.dumps(manifest)})
    assert result.stages.inventory == "partial" and result.occurrences[0].selected_version is None
    assert result.occurrences[0].scopes == ("runtime",) and not result.relationships
    semantic.append(record)
    manifest["dependencies"]["debug"] = "4.3.7"
    result, record = record_case("npm-explicit-declared-pin", {"package.json": json.dumps(manifest)})
    assert result.stages.inventory == "complete" and result.occurrences[0].selected_version == "4.3.7"
    assert result.occurrences[0].evidence_kind == "declared" and result.occurrences[0].selection_declaration_ids
    semantic.append(record)
    result, record = record_case(
        "npm-shared-semantic-budget",
        {"package-lock.json": json.dumps(npm_lock), "requirements.txt": "pip==26.0.1\n"},
        config=registry.DiscoveryConfig(semantic_checks=100),
    )
    assert result.stages.inventory == "failed" and result.occurrences == result.dependency_selectors == ()
    semantic.append(record)
    result, record = record_case(
        "npm-peer-context-unassessed",
        {
            "package-lock.json": json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "node_modules/debug": {"version": "4.3.7", "peerDependencies": {"ms": "^2"}},
                        "node_modules/ms": {"version": "2.1.3"},
                    },
                }
            )
        },
    )
    assert result.stages.inventory == "partial" and not result.relationships
    assert result.dependency_selectors[0].reason == "npm-peer-context-unassessed"
    semantic.append(record)

    for present in (False, True):
        packages = {
            "node_modules/foo": {
                "version": "1.0.0",
                "dependencies": {"bar": "https://alice:secret-token@example.invalid/a.tgz"},
            }
        }
        if present:
            packages["node_modules/bar"] = {"version": "1.0.0"}
        result, record = record_case(
            "npm-private-selector-" + ("present" if present else "missing"),
            {"package-lock.json": json.dumps({"lockfileVersion": 3, "packages": packages})},
        )
        assert result.stages.inventory == "partial" and not result.relationships
        assert b"secret-token" not in contract.canonical_bytes(result)
        assert result.dependency_selectors[0].declared_range is None
        assert result.dependency_selectors[0].reason == "unsupported-npm-dependency-selector"
        semantic.append(record)
    result, record = record_case(
        "npm-private-manifest-selector",
        {"package.json": json.dumps({"dependencies": {"foo": "https://alice:secret-token@example.invalid/a.tgz"}})},
    )
    assert result.stages.inventory == "partial" and result.declarations[0].declared_range is None
    assert b"secret-token" not in contract.canonical_bytes(result)
    semantic.append(record)
    for flag, scope in (("peer", ("peer",)), ("extraneous", ("unknown",))):
        result, record = record_case(
            "npm-" + flag + "-context",
            {
                "package-lock.json": json.dumps(
                    {"lockfileVersion": 3, "packages": {"node_modules/foo": {"version": "1.0.0", flag: True}}}
                )
            },
        )
        assert result.stages.inventory == "partial" and result.occurrences[0].scopes == scope
        assert result.coverage.inputs[0].reason == "unsupported-npm-package-selection-context"
        semantic.append(record)
    result, record = record_case(
        "npm-nested-manager-controls",
        {
            "package.json": json.dumps(
                {
                    "name": "fixture",
                    "version": "1.0.0",
                    "dependencies": {"foo": "1.0.0"},
                    "pnpm": {"overrides": {"foo": "2.0.0"}},
                }
            )
        },
    )
    assert (
        result.stages.inventory == "partial"
        and result.coverage.inputs[0].reason == "unsupported-npm-selection-controls"
    )
    semantic.append(record)

    result, record = record_case(
        "npm-strict-application-version",
        {
            "package.json": json.dumps(
                {"name": "fixture", "version": "9007199254740992.0.0", "dependencies": {"foo": "1.0.0"}}
            )
        },
    )
    assert result.stages.inventory == "partial" and not result.roots and not result.applications
    assert result.occurrences[0].selected_version == "1.0.0" and result.occurrences[0].root_id is None
    semantic.append(record)

    pnpm_lock = {
        "lockfileVersion": "9.0",
        "importers": {".": {"dependencies": {"alpha": {"specifier": "^1", "version": "1.2.3"}}}},
        "packages": {
            name: {"resolution": {"integrity": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}
            for name in ("alpha@1.2.3", "beta@2.0.0")
        },
        "snapshots": {"alpha@1.2.3": {"dependencies": {"beta": "2.0.0"}}, "beta@2.0.0": {}},
    }
    result, record = record_case("pnpm-exact-source-graph", {"pnpm-lock.yaml": yaml.safe_dump(pnpm_lock)})
    assert result.stages.inventory == "complete" and len(result.occurrences) == 2
    assert len(result.relationships) == 1 and not result.roots
    assert {value.directness for value in result.occurrences} == {"direct", "transitive"}
    assert all(value.root_id is None and value.activation == "unknown" for value in result.occurrences)
    semantic.append(record)

    env_lock = json.loads(json.dumps(pnpm_lock))
    env_lock["importers"]["."]["configDependencies"] = env_lock["importers"]["."].pop("dependencies")
    result, record = record_case(
        "pnpm-two-document-contexts", {"pnpm-lock.yaml": yaml.safe_dump_all([env_lock, pnpm_lock])}
    )
    assert len(result.occurrences) == 4 and len(result.relationships) == 2
    assert len({value.analysis_scope_id for value in result.occurrences}) == 2
    assert {value.scopes for value in result.occurrences} == {("build",), ("runtime",)}
    semantic.append(record)

    changed = json.loads(json.dumps(pnpm_lock))
    changed["importers"]["packages/tool"] = {"devDependencies": {"alpha": {"specifier": "^1", "version": "1.2.3"}}}
    result, record = record_case("pnpm-importer-scopes", {"pnpm-lock.yaml": yaml.safe_dump(changed)})
    assert len(result.occurrences) == 4 and len(result.relationships) == 2
    assert {value.scopes for value in result.occurrences} == {("development",), ("runtime",)}
    semantic.append(record)

    changed = json.loads(json.dumps(pnpm_lock))
    changed["importers"]["."]["dependencies"]["alpha"]["version"] = "1.2.3(peer@1.0.0)"
    changed["snapshots"] = {
        "alpha@1.2.3(peer@1.0.0)": {"dependencies": {"beta": "2.0.0"}},
        "alpha@1.2.3(peer@2.0.0)": {},
        "beta@2.0.0": {},
    }
    result, record = record_case("pnpm-peer-snapshot-keys", {"pnpm-lock.yaml": yaml.safe_dump(changed)})
    alpha = [value for value in result.occurrences if value.name == "alpha"]
    assert len(alpha) == 2 and {value.directness for value in alpha} == {"direct", "unknown"}
    assert len(result.relationships) == 1
    semantic.append(record)

    changed = json.loads(json.dumps(pnpm_lock))
    changed["importers"]["."]["dependencies"]["alpha"]["version"] = "1.2.3(peer@missing)"
    result, record = record_case("pnpm-no-peer-fallback", {"pnpm-lock.yaml": yaml.safe_dump(changed)})
    assert result.stages.inventory == "partial" and all(value.directness == "unknown" for value in result.occurrences)
    semantic.append(record)

    changed = json.loads(json.dumps(pnpm_lock))
    changed["importers"]["."]["dependencies"]["alpha"]["specifier"] = "https://alice:secret-token@example.invalid/a.tgz"
    result, record = record_case("pnpm-private-unsupported-selector", {"pnpm-lock.yaml": yaml.safe_dump(changed)})
    assert result.stages.inventory == "partial" and result.declarations[0].declared_range is None
    assert b"secret-token" not in contract.canonical_bytes(result)
    semantic.append(record)

    result, record = record_case(
        "pnpm-yaml-alias-refused", {"pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages: &x {}\nsnapshots: *x\n"}
    )
    assert result.stages.inventory == "partial" and not result.occurrences
    assert result.coverage.inputs[0].reason == "unsupported-yaml-alias-or-anchor"
    semantic.append(record)
    result, record = record_case(
        "pnpm-shared-budget-refusal",
        {
            "pnpm-lock.yaml": yaml.safe_dump(pnpm_lock),
            "requirements.txt": "pip==26.0.1\n",
        },
        config=registry.DiscoveryConfig(semantic_checks=100),
    )
    assert (
        result.stages.inventory == "failed" and result.occurrences == result.declarations == result.relationships == ()
    )
    semantic.append(record)

    changed = json.loads(json.dumps(pnpm_lock))
    changed["packages"]["alpha@1.2.3"] = {}
    result, record = record_case("pnpm-incomplete-resolution-fragment", {"pnpm-lock.yaml": yaml.safe_dump(changed)})
    assert result.stages.inventory == "partial" and len(result.occurrences) == 2
    assert result.coverage.inputs[0].reason == "incomplete-pnpm-package-resolution"
    semantic.append(record)

    result, record = record_case(
        "pnpm-invalid-unicode-refused",
        {
            "pnpm-lock.yaml": 'lockfileVersion: "9.0"\npackages:\n  alpha@1.0.0:\n    resolution: {tarball: "https://example.invalid/\\uD800"}\n',
            "requirements.txt": "pip==26.0.1\n",
        },
    )
    assert result.stages.inventory == "partial" and [value.name for value in result.occurrences] == ["pip"]
    assert (
        next(value for value in result.coverage.inputs if value.format == "pnpm-lock").reason == "invalid-yaml-unicode"
    )
    semantic.append(record)

    yarn_classic = """# yarn lockfile v1
"alpha@^1":
  version "1.2.3"
  resolved "https://registry.npmjs.org/alpha/-/alpha-1.2.3.tgz"
  dependencies:
    beta "^2"
"beta@^2":
  version "2.0.0"
  resolved "https://registry.npmjs.org/beta/-/beta-2.0.0.tgz"
"""
    yarn_modern = {
        "__metadata": {"version": "10", "cacheKey": "10c0"},
        "alpha@npm:^1": {
            "version": "1.2.3",
            "resolution": "alpha@npm:1.2.3",
            "linkType": "hard",
            "dependencies": {"beta": "npm:^2"},
        },
        "beta@npm:^2": {"version": "2.0.0", "resolution": "beta@npm:2.0.0", "linkType": "hard"},
    }
    for name, text in (
        ("yarn-classic-source-graph", yarn_classic),
        ("yarn-modern-source-graph", yaml.safe_dump(yarn_modern)),
    ):
        result, record = record_case(name, {"yarn.lock": text})
        assert result.stages.inventory == "complete" and len(result.occurrences) == 2 and len(result.relationships) == 1
        assert (
            not result.roots
            and not result.applications
            and all(value.directness == "unknown" for value in result.occurrences)
        )
        semantic.append(record)

    result, record = record_case(
        "yarn-one-entry-aliases", {"yarn.lock": yarn_classic.replace('"alpha@^1":', '"alpha@^1", "alpha@~1":')}
    )
    assert len(result.occurrences) == 2 and len(result.relationships) == 1
    semantic.append(record)
    result, record = record_case(
        "yarn-equal-separate-entries",
        {
            "yarn.lock": yarn_classic
            + '\n"beta@~2":\n  version "2.0.0"\n  resolved "https://registry.npmjs.org/beta/-/beta-2.0.0.tgz"\n'
        },
    )
    assert len(result.occurrences) == 3 and len({value.id for value in result.occurrences if value.name == "beta"}) == 2
    semantic.append(record)
    result, record = record_case(
        "yarn-no-descriptor-fallback", {"yarn.lock": yarn_classic.replace('"beta@^2":', '"beta@~2":')}
    )
    assert result.stages.inventory == "partial" and len(result.occurrences) == 2 and not result.relationships
    semantic.append(record)

    changed = json.loads(json.dumps(yarn_modern))
    changed["beta@npm:^2, beta@npm:~2"] = {"version": "invalid"}
    result, record = record_case("yarn-refused-alias-still-blocks", {"yarn.lock": yaml.safe_dump(changed)})
    assert result.stages.inventory == "partial" and len(result.occurrences) == 2 and not result.relationships
    semantic.append(record)
    changed = json.loads(json.dumps(yarn_modern))
    changed["alpha@npm:^1"]["dependencies"]["beta"] = "https://user:secret-token@example.invalid/a.tgz"
    result, record = record_case("yarn-private-selector-refused", {"yarn.lock": yaml.safe_dump(changed)})
    assert result.stages.inventory == "partial" and result.dependency_selectors[0].declared_range is None
    assert b"secret-token" not in contract.canonical_bytes(result)
    semantic.append(record)
    changed = json.loads(json.dumps(yarn_modern))
    changed["alpha@npm:^1"].pop("resolution")
    result, record = record_case("yarn-incomplete-resolution-fragment", {"yarn.lock": yaml.safe_dump(changed)})
    assert result.stages.inventory == "partial" and len(result.occurrences) == 2
    assert result.coverage.inputs[0].reason == "incomplete-yarn-package-resolution"
    semantic.append(record)
    result, record = record_case(
        "yarn-global-budget-refusal",
        {"yarn.lock": yarn_classic, "requirements.txt": "pip==26.0.1\n"},
        config=registry.DiscoveryConfig(semantic_checks=100),
    )
    assert result.stages.inventory == "failed" and not result.occurrences and not result.declarations
    semantic.append(record)

    changed = json.loads(json.dumps(yarn_modern))
    changed["beta@^2"] = changed.pop("beta@npm:^2")
    changed["alpha@npm:^1"]["dependencies"]["beta"] = "^2"
    result, record = record_case("yarn-modern-missing-protocol-refused", {"yarn.lock": yaml.safe_dump(changed)})
    assert result.stages.inventory == "partial" and not result.relationships
    assert [value.name for value in result.occurrences] == ["alpha"]
    semantic.append(record)
    result, record = record_case(
        "yarn-classic-alias-identity-refused",
        {
            "yarn.lock": '# yarn lockfile v1\n"alpha@npm:beta@^2":\n  version "2.0.0"\n  resolved "https://registry.npmjs.org/beta/-/beta-2.0.0.tgz"\n'
        },
    )
    assert result.stages.inventory == "partial" and not result.occurrences
    semantic.append(record)

    changed = json.loads(json.dumps(yarn_modern))
    changed["alpha@npm:^1"].pop("dependencies")
    changed["alpha@npm:^1"]["peerDependencies"] = {"beta": ">= 1 < 3"}
    result, record = record_case("yarn-modern-bare-peer-range", {"yarn.lock": yaml.safe_dump(changed)})
    assert result.stages.inventory == "partial" and len(result.occurrences) == 2 and not result.relationships
    (selector,) = result.dependency_selectors
    assert selector.declared_range == ">= 1 < 3" and selector.reason == "yarn-peer-context-unassessed"
    semantic.append(record)

    corpus = json.loads(Path("tests/fixtures/inventory/corpus.json").read_text())
    assert len(corpus) == 64
    fixtures = []
    for fixture in corpus:
        _result, record = record_case(fixture["id"], fixture["files"], links=fixture.get("symlinks"))
        fixtures.append(record)
    print(
        json.dumps(
            {
                "status": "native-installed-inventory-composition-passed",
                "python": platform.python_version(),
                "architecture": platform.machine(),
                "packaging": packaging.__version__,
                "pydantic": pydantic.__version__,
                "poetry_core": poetry_constraints.GRAMMAR_VERSION,
                "pyyaml": yaml.__version__,
                "npm_semver_manifest_sha256": npm_selectors.verify_vendor(),
                "yarn_syml_manifest_sha256": yarn_legacy.verify_vendor(),
                "yarn_legacy_entry_sha256": hashlib.sha256(
                    Path(yarn_legacy.__file__).with_name("yarn_legacy.cjs").read_bytes()
                ).hexdigest(),
                "npm_selector_entry_sha256": hashlib.sha256(
                    Path(npm_selectors.__file__).with_name("node_selectors.cjs").read_bytes()
                ).hexdigest(),
                "node": __import__("subprocess")
                .check_output(
                    ["/usr/bin/node", "--version"], env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, text=True
                )
                .strip(),
                "source_modules": {
                    Path(m.__file__).name: hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest() for m in modules
                },
                "semantic_cases": semantic,
                "epoch_failure": "no-consumable-records",
                "fixtures": fixtures,
                "scope": "finite requirements/static-manifest/Python-lock/npm/pnpm/Yarn-source composition assertions and 64 repeated canonical digests; no full rich oracle agreement, production integration, matching or kernel/resource qualification",
            },
            sort_keys=True,
            indent=2,
        )
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"status": "native-composition-failed", "reason": type(error).__name__}, sort_keys=True))
        raise
