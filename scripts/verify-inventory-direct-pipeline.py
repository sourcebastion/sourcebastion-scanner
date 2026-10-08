"""Finite installed direct-controller proof; no consumer or host admission."""

import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import sys
import tempfile
import time

FIXTURE = Path("evaluation/m046/real-grype-native-fixture-v3.json")
FIXTURE_SHA256 = "4009ef7f9ee8fee6a221897959b0f23b8f1651e8cafd4328ae62ae21859c11de"


def render(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    deadline = time.monotonic() + 150
    signal.alarm(150)
    if sys.flags.optimize or os.getuid() == 0:
        raise RuntimeError("unsafe-native-proof-runtime")
    from sourcebastion.inventory import contract
    from sourcebastion.inventory.artifacts import ArtifactStore
    from sourcebastion.inventory.budget import PipelineBudget
    from sourcebastion.inventory.direct_pipeline import run_direct
    from sourcebastion.inventory.inputs import Source
    from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256

    def guard():
        if time.monotonic() >= deadline:
            raise RuntimeError("direct-proof-deadline-exceeded")

    def modules(root):
        result = {}
        for path in sorted(root.rglob("*")):
            guard()
            if path.is_file() and path.suffix in {".py", ".cjs", ".js", ".json", ".mjs"}:
                if len(result) >= 256 or path.stat().st_size > 2 * 1024**2:
                    raise RuntimeError("direct-proof-module-budget-exceeded")
                result[path.relative_to(root).as_posix()] = sha(path.read_bytes())
        return result

    installed = Path(contract.__file__).resolve().parent
    assert not installed.is_relative_to(Path.cwd().resolve())
    source_modules = modules(Path("sourcebastion/inventory"))
    assert modules(installed) == source_modules
    fixture_raw = FIXTURE.read_bytes()
    assert sha(fixture_raw) == FIXTURE_SHA256
    fixture = json.loads(fixture_raw)
    config = DiscoveryConfig(mappings=tuple(tuple(row) for row in fixture["discovery_config"]["mappings"]))
    source_identity = {
        row["path"]: {"sha256": row["sha256"], "bytes": len(row["utf8"].encode())} for row in fixture["files"]
    }
    producer = contract.Producer(
        name="native-direct-controller-proof",
        version="1",
        code_sha256=sha(render(source_modules)),
        registry_sha256=REGISTRY_SHA256,
        config_sha256=config.sha256,
    )
    with tempfile.TemporaryDirectory(prefix="direct-pipeline-") as temporary:
        private = Path(temporary)
        root, output = private / "source", private / "output"
        root.mkdir(mode=0o700)
        output.mkdir(mode=0o700)
        for row in fixture["files"]:
            raw = row["utf8"].encode()
            assert sha(raw) == row["sha256"]
            path = root / row["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        with Source(root) as source:
            budget = PipelineBudget(source, config=config, deadline=deadline)
            with ArtifactStore(output, limits=contract.InventoryLimits(), check=budget.check) as store:
                result = run_direct(
                    source,
                    budget=budget,
                    config=config,
                    producer=producer,
                    source_sha256=sha(render(source_identity)),
                    store=store,
                )
                assert result.finalized
                receipt = json.loads(result.receipt)
                assert receipt["matching"] == "not_run" and receipt["kernel_admission"] == "not_observed"
                assert set(receipt["stages"].values()) == {"succeeded"}
                artifacts = {}
                for fact in store.facts:
                    raw = (output / fact.name).read_bytes()
                    assert len(raw) == fact.bytes and sha(raw) == fact.sha256
                    artifacts[fact.name] = json.loads(raw)
                value, sbom = artifacts["inventory.json"], artifacts["sbom.cdx.json"]
                assert value["stages"]["export"] == value["stages"]["matching"] == "not-run"
                assert len(value["occurrences"]) == 5 and len(sbom["components"]) == 4
                selected = {row["source"]["path"]: row for row in value["occurrences"] if row["selected_version"]}
                assert set(selected) == {row["path"] for row in fixture["expected"]["selected"]}
                for expected in fixture["expected"]["selected"]:
                    row = selected[expected["path"]]
                    assert row["name"] == expected["name"] and row["selected_version"] == expected["version"]
                    assert row["source"]["source_sha256"] == source_identity[expected["path"]]["sha256"]
                    assert row["source"]["locator"] == "line:" + str(expected["line"])
                    assert row["activation"] == expected["activation"] and row["hashes"] == expected["hashes"]
                    assert row["marker"] == expected.get("marker")
                unselected = [row for row in value["occurrences"] if row["selected_version"] is None]
                assert len(unselected) == len(fixture["expected"]["unselected"]) == 1
                row, expected = unselected[0], fixture["expected"]["unselected"][0]
                assert row["name"] == expected["name"] and row["declared_range"] == expected["declared_range"]
                assert row["source"]["path"] == expected["path"]
                assert row["source"]["source_sha256"] == source_identity[expected["path"]]["sha256"]
                assert row["source"]["locator"] == "line:" + str(expected["line"])
                assert row["selected_version"] is None and row["purl"] == "pkg:pypi/requests"
                assert row["id"] not in {component["bom-ref"] for component in sbom["components"]}
                assert {row["bom-ref"] for row in sbom["components"]} == {row["id"] for row in selected.values()}
                store.validate()
                budget.check()
                record = {
                    "schema_version": "m046.native-direct-pipeline-proof/1",
                    "python": platform.python_version(),
                    "machine": platform.machine(),
                    "installed_modules": source_modules,
                    "fixture_sha256": sha(fixture_raw),
                    "source_files": source_identity,
                    "receipt": receipt,
                    "artifacts": artifacts,
                    "semantic_checks_after_proof": budget.consumed,
                    "scope": "inactive child stages only; no consumer, kernel CPU-time or lifecycle admission",
                }
    guard()
    raw = render(record)
    assert len(raw) <= 1024**2
    print(raw.decode())


if __name__ == "__main__":
    main()
