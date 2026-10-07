#!/usr/bin/env python3
"""Finite installed contract/grammar smoke on each native release image.

This is not a canonical adapter, matcher or whole-pipeline qualification.
Only synthetic reviewed inputs are read; no manager/forge/network call occurs.
"""

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import platform
import signal
import sys

import packaging
import packaging.markers
import pydantic

from sourcebastion.inventory import contract, discovery, inputs, markers, python_manifests, registry, requirements


def must_refuse(function, code):
    try:
        function()
    except ValueError as error:
        assert code in str(error), type(error).__name__
    else:
        raise AssertionError("missing-expected-refusal")


def main():
    if sys.flags.optimize:
        raise RuntimeError("optimized-probe-runtime-refused")
    signal.alarm(60)
    assert packaging.__version__ == "26.3"
    modules = (contract, discovery, inputs, markers, python_manifests, registry, requirements)
    for module in modules:
        assert "/site-packages/sourcebastion/inventory/" in module.__file__

    def no_host(*_args, **_kwargs):
        raise AssertionError("host-marker-input-not-authorized")

    packaging.markers.default_environment = no_host
    packaging.markers.Marker.evaluate = no_host
    environment = contract.Environment(policy="explicit-target", python_version="3.12.9", platform="linux")
    assert markers.marker_activation('python_version < "3.13"', environment).activation == "active"
    assert markers.marker_activation('python_version >= "3.13"', environment).activation == "inactive"
    for expression in ('extra == "test"', "os_name == sys_platform", 'platform_machine == "x86_64"'):
        assert markers.marker_activation(expression, environment).activation == "unknown"
    assert markers.disjoint('python_version < "3.13"', 'python_version >= "3.13"')
    must_refuse(
        lambda: contract.Environment(
            policy="explicit-target", python_version="3.12", marker_inputs=(("python_full_version", "3.14.8"),)
        ),
        "contradictory-environment-input",
    )
    assert contract.go_module_hash("h1:" + "A" * 43 + "=").digest == "0" * 64

    content = b"pip==26.0.1\n"
    sha = hashlib.sha256(content).hexdigest()
    source = contract.Locator(path="requirements.txt", source_sha256=sha, locator="line:1", parser="test/1")
    occurrence = contract.Occurrence(
        id=contract.identifier("occurrence", [source.model_dump(), "pip", "26.0.1"]),
        source=source,
        ecosystem="pypi",
        name="pip",
        purl=contract.package_purl("pypi", "pip", "26.0.1"),
        evidence_kind="declared",
        selected_version="26.0.1",
    )
    inventory = contract.Inventory(
        source_sha256=sha,
        producer=contract.Producer(
            name="synthetic-native-probe",
            version="1",
            code_sha256=sha,
            registry_sha256=registry.REGISTRY_SHA256,
            config_sha256=registry.DiscoveryConfig().sha256,
        ),
        environment=environment,
        environment_sha256=environment.sha256,
        occurrences=(occurrence,),
        coverage=contract.Coverage(
            discovery="complete",
            enumeration="complete",
            version_resolution="complete",
            graph="unknown",
            environment="unknown",
            inputs=(
                contract.InputCoverage(
                    source_path=source.path,
                    source_sha256=sha,
                    format="pip-requirements",
                    parser=source.parser,
                    disposition="parsed",
                    reason="synthetic-probe",
                ),
            ),
        ),
        stages=contract.StageStates(inventory="complete"),
    )
    canonical = contract.canonical_bytes(inventory)
    assert contract.Inventory.model_validate_json(canonical) == inventory
    must_refuse(lambda: contract.canonical_bytes(inventory, max_bytes=len(canonical) - 1), "output-budget")
    must_refuse(lambda: contract.canonical_bytes(inventory, max_nodes=1), "structure-budget")
    forged = inventory.model_copy(
        update={"coverage": inventory.coverage.model_copy(update={"refusal_codes": ("deadline",)})}
    )
    must_refuse(lambda: contract.canonical_bytes(forged), "cannot-be-promoted")
    must_refuse(
        lambda: contract.canonical_bytes(inventory.model_copy(update={"source_sha256": "wrong"})), "source_sha256"
    )

    fixture_results = []
    corpus = json.loads(Path("tests/fixtures/inventory/corpus.json").read_text())
    assert len(corpus) == 64
    supported = {"python-pyproject", "python-setup-cfg", "python-setup-static"}
    for fixture in corpus:
        for path, content in sorted(fixture["files"].items()):
            fmt = registry.format_for(path, registry.DiscoveryConfig())
            if fmt not in supported:
                continue
            document = python_manifests.parse(path, content.encode(), fmt)
            assert document == python_manifests.parse(path, content.encode(), fmt)
            assert document.sha256 == hashlib.sha256(content.encode()).hexdigest()
            encoded = json.dumps(asdict(document), sort_keys=True, separators=(",", ":")).encode()
            fixture_results.append(
                {
                    "fixture": fixture["id"],
                    "path": path,
                    "format": fmt,
                    "disposition": document.disposition,
                    "reason": document.reason,
                    "document_sha256": hashlib.sha256(encoded).hexdigest(),
                }
            )
    assert fixture_results
    # Parse grammar in a synthetic setup.py; no module import or setup call.
    refusal = python_manifests.parse(
        "setup.py", b'import os\nos.system("touch SHOULD_NEVER_EXECUTE")\n', "python-setup-static"
    )
    assert refusal.disposition == "unsupported" and not Path("SHOULD_NEVER_EXECUTE").exists()
    print(
        json.dumps(
            {
                "status": "native-installed-inventory-foundation-passed",
                "python": platform.python_version(),
                "architecture": platform.machine(),
                "packaging": packaging.__version__,
                "pydantic": pydantic.__version__,
                "source_modules": {
                    Path(m.__file__).name: hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest() for m in modules
                },
                "canonical_sha256": hashlib.sha256(canonical).hexdigest(),
                "manifest_fixtures": fixture_results,
                "scope": "finite contract/grammar/marker smoke; no canonical composition, vulnerability matching, kernel counters or full pipeline acceptance",
            },
            sort_keys=True,
            indent=2,
        )
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"status": "native-foundation-failed", "reason": type(error).__name__}, sort_keys=True))
        raise
