"""Finite native fixed-controller evidence, not host/kernel admission."""

import hashlib
import json
import os
import platform
from pathlib import Path
import runpy
import sys
import time

WORK = Path("/src")
ROOT = Path("/out")
FIXTURE = WORK / "evaluation/m046/real-grype-native-fixture-v3.json"
PINS = WORK / "evaluation/m046/real-grype-native-binaries-v1.json"
PREPARATION = Path("/preparation/advisory.json")
ADVISORIES = Path("/advisories")


def render(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    if sys.flags.optimize:
        raise RuntimeError("optimized-probe-runtime-refused")
    from sourcebastion.inventory import consumer_runtime, contract, dependency_job
    from sourcebastion.inventory.artifacts import ArtifactStore
    from sourcebastion.inventory.budget import PipelineBudget
    from sourcebastion.inventory.consumer_runtime import RuntimeSpec
    from sourcebastion.inventory.contract import Inventory, InventoryLimits, Producer
    from sourcebastion.inventory.inputs import Source
    from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256

    assert os.getuid() != 0
    os.umask(0o077)
    fixture_raw = FIXTURE.read_bytes()
    assert sha(fixture_raw) == "4009ef7f9ee8fee6a221897959b0f23b8f1651e8cafd4328ae62ae21859c11de"
    fixture, pins = json.loads(fixture_raw), json.loads(PINS.read_bytes())
    assert PREPARATION.stat().st_size <= 65536
    preparation_raw = PREPARATION.read_bytes()
    preparation = json.loads(preparation_raw)
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    pin = pins["architectures"][architecture]
    status = preparation["status"]
    runtime = RuntimeSpec(
        pin["binary_sha256"],
        pin["binary_bytes"],
        tuple((name, row["sha256"], row["bytes"]) for name, row in sorted(preparation["binding"]["files"].items())),
        status["schemaVersion"],
        status["built"],
    )
    assert consumer_runtime.BINARY == Path("/usr/local/bin/grype")
    assert consumer_runtime.ADVISORIES == dependency_job.ADVISORIES == ADVISORIES
    assert not Path(contract.__file__).resolve().is_relative_to(WORK)
    installed = Path(contract.__file__).resolve().parent
    modules = {
        p.relative_to(installed).as_posix(): sha(p.read_bytes())
        for p in sorted(installed.rglob("*"))
        if p.is_file() and p.suffix in {".py", ".js", ".cjs", ".mjs", ".json"}
    }
    # Exactly the reviewed module set. Adding a module to the installed
    # inventory package must fail here until that module is reviewed;
    # 97 includes `imported_sbom.py`.
    assert len(modules) == 97
    assert all(
        sha((WORK / "sourcebastion/inventory" / name).read_bytes()) == digest for name, digest in modules.items()
    )
    assert ROOT.is_dir() and not any(ROOT.iterdir())
    source_root, output = Path("/fixture"), ROOT / "artifacts"
    output.mkdir(mode=0o700)
    for name, raw in (
        ("preparation.json", preparation_raw),
        ("fixture.json", fixture_raw),
        ("pins.json", PINS.read_bytes()),
    ):
        with (ROOT / name).open("xb") as stream:
            stream.write(raw)
    expected_files = {row["path"]: row for row in fixture["files"]}
    config = DiscoveryConfig(mappings=tuple(tuple(row) for row in fixture["discovery_config"]["mappings"]))
    producer = Producer(
        name="native-fixed-dependency-controller",
        version="1",
        code_sha256=sha(render(modules)),
        registry_sha256=REGISTRY_SHA256,
        config_sha256=config.sha256,
    )
    admission_start = time.monotonic()
    absolute_deadline = admission_start + 150
    with Source(source_root) as source:
        budget = PipelineBudget(source, config=config, deadline=absolute_deadline)
        entries = tuple(source.discover())
        assert all(row.kind in {"file", "directory"} for row in entries)
        assert {row.path for row in entries if row.kind == "file"} == expected_files.keys()
        for path, row in expected_files.items():
            budget.check()
            observed = source.read(path)
            assert observed.content == row["utf8"].encode() and observed.sha256 == row["sha256"]
        with ArtifactStore(output, limits=InventoryLimits(), check=budget.check) as store:
            result = dependency_job.run_dependency(
                source,
                budget=budget,
                config=config,
                producer=producer,
                source_sha256=sha(render(expected_files)),
                store=store,
                runtime=runtime,
            )
            elapsed = time.monotonic() - admission_start
            with (ROOT / "controller-receipt.json").open("xb") as stream:
                stream.write(result.receipt)
            receipt = json.loads(result.receipt)
            assert result.finalized and elapsed < 150, receipt
            assert set(receipt["stages"].values()) == {"succeeded"}
            assert receipt["kernel_admission"] == "not_observed" and receipt["authority"] == "child-artifact-facts-only"
            assert receipt["execution"] == {"exit_code": 0, "lifecycle": "leader-reaped-only"}
            store.validate()
    canonical = (output / "inventory.json").read_bytes()
    value = Inventory.model_validate_json(canonical)
    assert contract.canonical_bytes(value) == canonical
    assert (
        len(value.occurrences) == 5 and not value.relationships and not value.roots and not value.installed_environments
    )
    assert value.stages.matching == value.stages.export == "not-run"
    by_path = {row.source.path: row for row in value.occurrences}
    assert len(by_path) == 5
    required = {}
    for wanted in fixture["expected"]["selected"]:
        row = by_path[wanted["path"]]
        assert row.name == wanted["name"] and row.selected_version == wanted["version"]
        assert row.source.locator == "line:1" and row.source.source_sha256 == expected_files[wanted["path"]]["sha256"]
        assert row.purl == "pkg:pypi/" + wanted["name"] + "@" + wanted["version"]
        assert row.activation == wanted["activation"] and row.marker == wanted.get("marker")
        assert [entry.model_dump(mode="json") for entry in row.hashes] == wanted["hashes"]
        assert row.root_id is row.installed_environment_id is None and row.directness == "unknown" and not row.scopes
        required[row.id] = wanted["required_advisories"]
    unselected = by_path["range/requirements.in"]
    assert (
        unselected.name == "requests"
        and unselected.declared_range == ">=2.19,<3"
        and unselected.selected_version is None
    )
    assert unselected.purl == "pkg:pypi/requests" and unselected.source.locator == "line:1"
    assert unselected.source.source_sha256 == expected_files["range/requirements.in"]["sha256"]
    assert unselected.id not in required
    recovered = json.loads((output / "recovery.json").read_bytes())
    raw = (output / "grype.json").read_bytes()
    report = json.loads(raw)
    assert len(report["matches"]) == len(recovered["matches"]) >= 18
    assert set(recovered["occurrence_contexts"]) == set(required)
    for identifier, context in recovered["occurrence_contexts"].items():
        assert context == next(row.model_dump(mode="json") for row in value.occurrences if row.id == identifier)
    helpers = runpy.run_path(
        str(WORK / "scripts/verify-inventory-real-grype.py"), run_name="reviewed_advisory_predicates"
    )
    for identifier, groups in required.items():
        for group in groups:
            aliases = {(row["id"], row["namespace"]) for row in group}
            assert any(
                row["occurrence_id"] == identifier
                and helpers["known_advisory"](report["matches"][row["ordinal"]], aliases)
                for row in recovered["matches"]
            )
    configuration_raw = (output / "consumer-config.json").read_bytes()
    assert sha(configuration_raw) == receipt["consumer"]["config_sha256"]
    assert json.loads(configuration_raw)["environment"]["GOMAXPROCS"] == "2"
    assert json.loads(configuration_raw)["yaml_sha256"] == sha((output / "grype.yaml").read_bytes())
    for fact in receipt["artifacts"]:
        raw_fact = (output / fact["name"]).read_bytes()
        assert fact["bytes"] == len(raw_fact) and fact["sha256"] == sha(raw_fact)
    proof = {
        "status": "native-fixed-consumer-controller-finite-passed",
        "controller_wall_seconds": elapsed,
        "python": platform.python_version(),
        "architecture": platform.machine(),
        "uid": os.getuid(),
        "gid": os.getgid(),
        "controller_deadline_seconds": 150,
        "controller_receipt_sha256": sha(result.receipt),
        "fixture_sha256": sha(fixture_raw),
        "prepared_advisory_manifest_sha256": sha(PREPARATION.read_bytes()),
        "source_modules": modules,
        "selected_ids": sorted(required),
        "unselected_id": unselected.id,
        "matches": len(report["matches"]),
        "all_required_advisory_groups": True,
        "scope": "Finite installed native controller proof with fixed paths and one150wallledger including held runtime/advisory hashing, version/status, composition/export/analysis/recovery/finalization. Parent proof preparation/module enumeration and post-return pure inspection remain outside this library timer; Docker flags do not prove aggregate120CPU enforcement or actual kernel counters/owned all-descendant cleanup. No CLI/customer-route/fullrelease-module-admission/wholeS04 acceptance.",
    }
    with (ROOT / "proof.json").open("xb") as stream:
        stream.write(render(proof))
    print(
        json.dumps(
            {key: proof[key] for key in ("status", "controller_wall_seconds", "controller_receipt_sha256", "matches")}
        )
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        failure = {"status": "native-fixed-consumer-controller-finite-failed", "reason": type(error).__name__}
        if ROOT.is_dir():
            try:
                descriptor = os.open(ROOT / "failure.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(render(failure))
            except OSError:
                pass
        print(json.dumps(failure, sort_keys=True))
        raise
