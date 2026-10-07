#!/usr/bin/env python3
"""Finite installed pip composition checks plus 64-case repeatability records.

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

from sourcebastion.inventory import (
    compose_requirements,
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
        return compose_requirements.compose_requirements(
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
    modules = (compose_requirements, contract, discovery, inputs, markers, python_manifests, registry, requirements)
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
                "source_modules": {
                    Path(m.__file__).name: hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest() for m in modules
                },
                "semantic_cases": semantic,
                "epoch_failure": "no-consumable-records",
                "fixtures": fixtures,
                "scope": "finite pip composition assertions and 64 repeated canonical digests; no full rich oracle agreement, production integration, matching or kernel/resource qualification",
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
