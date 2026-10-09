"""Finite CI image preparation/inspection; never parent scan admission."""

import hashlib
from importlib import metadata
import json
import os
from pathlib import Path, PurePosixPath
import platform
import runpy
import stat
import sys
import time

WORK = Path("/src")
PROOF = Path("/proof")
SOURCE = Path("/source")
OUTPUT = Path("/out")
PREPARATION = Path("/preparation/advisory.json")
FIXTURE = WORK / "evaluation/m046/real-grype-native-fixture-v3.json"
PINS = WORK / "evaluation/m046/real-grype-native-binaries-v1.json"
FIXTURE_SHA256 = "4009ef7f9ee8fee6a221897959b0f23b8f1651e8cafd4328ae62ae21859c11de"
NAMES = {
    "inventory.json", "sbom.cdx.json", "recovery.json", "grype.json", "grype.stderr",
    "grype-version.json", "grype-version.stderr", "grype-status.json",
    "grype-status.stderr", "consumer-config.json", "grype.yaml",
}


def render(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        assert 0 <= info.st_size <= maximum
        raw = bytearray()
        while len(raw) < info.st_size:
            chunk = os.read(fd, min(65536, info.st_size - len(raw)))
            assert chunk
            raw.extend(chunk)
        assert not os.read(fd, 1)
        assert file_metadata(os.fstat(fd)) == file_metadata(info)
        return bytes(raw)
    finally:
        os.close(fd)


def save(name, value):
    with (PROOF / name).open("xb") as stream:
        stream.write(render(value))


def file_metadata(info):
    # Reading can change atime; every other retained custody field is compared.
    return [
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    ]


def proc_value(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(4097)
    assert 0 < len(raw) <= 4096
    return raw.decode()


def fixture_facts(fixture):
    expected = {row["path"]: row for row in fixture["files"]}
    assert len(expected) == len(fixture["files"]) == 5
    facts, seen, directories = {}, set(), {".": file_metadata(SOURCE.lstat())}
    for root, dirs, files in os.walk(SOURCE, followlinks=False):
        assert len(seen) + len(directories) + len(dirs) + len(files) <= 32
        for name in dirs:
            path = Path(root) / name
            assert stat.S_ISDIR(path.lstat().st_mode)
            directories[path.relative_to(SOURCE).as_posix()] = file_metadata(path.lstat())
        for name in files:
            path = Path(root) / name
            relative = path.relative_to(SOURCE).as_posix()
            assert relative in expected and relative not in seen
            raw = read(path, 2 * 1024**2)
            assert raw == expected[relative]["utf8"].encode()
            assert sha(raw) == expected[relative]["sha256"]
            facts[relative] = dict(sha256=sha(raw), bytes=len(raw), metadata=file_metadata(path.lstat()))
            seen.add(relative)
    assert seen == expected.keys()
    expected_directories = {"."}
    for name in expected:
        expected_directories.update(str(parent) for parent in PurePosixPath(name).parents)
    assert directories.keys() == expected_directories
    return dict(files=facts, directories=directories)


def installed_bindings():
    from sourcebastion import inventory_entrypoint
    from sourcebastion.inventory import contract

    entry = Path(inventory_entrypoint.__file__).resolve()
    package = entry.parent
    assert not package.is_relative_to(WORK)
    assert entry.name == "inventory_entrypoint.py"
    distribution = metadata.distribution("sourcebastion-scanner")
    payloads = {}
    for row in distribution.files or ():
        name = row.as_posix()
        if not name.startswith("sourcebastion/") or "/__pycache__/" in name or name.endswith(".pyc"):
            continue
        relative = PurePosixPath(name)
        assert not relative.is_absolute() and ".." not in relative.parts
        assert name not in payloads and len(payloads) < 512
        actual = Path(distribution.locate_file(row)).resolve()
        assert actual.is_relative_to(package)
        raw = read(actual, 2 * 1024**2)
        assert raw == read(WORK / name, 2 * 1024**2)
        payloads[name] = dict(sha256=sha(raw), bytes=len(raw))
    assert len(payloads) == 137
    expected = {
        "sourcebastion/" + path.relative_to(WORK / "sourcebastion").as_posix()
        for path in (WORK / "sourcebastion").rglob("*")
        if path.is_file() and (
            path.suffix == ".py" or path.is_relative_to(WORK / "sourcebastion/inventory/vendor")
            or path.name in {"node_selectors.cjs", "yarn_legacy.cjs"}
            or path.is_relative_to(WORK / "sourcebastion/data/frameworks")
            or path.is_relative_to(WORK / "sourcebastion/templates")
        ) and "__pycache__" not in path.parts
    }
    assert payloads.keys() == expected
    inventory = Path(contract.__file__).resolve().parent
    modules = {
        path.relative_to(inventory).as_posix(): sha(read(path, 2 * 1024**2))
        for path in sorted(inventory.rglob("*"))
        if path.is_file() and path.suffix in {".py", ".js", ".cjs", ".mjs", ".json"}
    }
    # Exactly the reviewed module set; 97 includes `imported_sbom.py`.
    assert len(modules) == 97
    return dict(
        package_version=distribution.version, package_payloads=payloads,
        inventory_modules=modules, entrypoint_sha256=sha(read(entry, 65536)),
        scope="Own scanner distribution payload map plus separate entrypoint; not third-party/interpreter closure or release qualification",
    )


def common():
    if sys.flags.optimize:
        raise RuntimeError("optimized-probe-runtime-refused")
    if not sys.flags.isolated or os.getuid() == 0:
        raise RuntimeError("isolated-nonroot-probe-runtime-required")
    from sourcebastion.inventory.consumer_runtime import RuntimeSpec
    from sourcebastion.inventory.registry import DiscoveryConfig

    os.umask(0o077)
    raw = read(FIXTURE, 65536)
    assert sha(raw) == FIXTURE_SHA256
    fixture = json.loads(raw)
    preparation_raw = read(PREPARATION, 65536)
    preparation = json.loads(preparation_raw)
    pins_raw = read(PINS, 65536)
    pins = json.loads(pins_raw)
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    pin = pins["architectures"][architecture]
    runtime = RuntimeSpec(
        pin["binary_sha256"], pin["binary_bytes"],
        tuple((name, row["sha256"], row["bytes"]) for name, row in sorted(preparation["binding"]["files"].items())),
        preparation["status"]["schemaVersion"], preparation["status"]["built"],
    )
    config = DiscoveryConfig(mappings=tuple(tuple(row) for row in fixture["discovery_config"]["mappings"]))
    binding = installed_bindings()
    provenance = dict(
        fixture_sha256=sha(raw), preparation_sha256=sha(preparation_raw),
        pins_sha256=sha(pins_raw), bindings=binding,
        architecture=architecture, python=platform.python_version(), uid=os.getuid(), gid=os.getgid(),
    )
    return fixture, runtime, config, provenance


def prepare():
    fixture, runtime, config, provenance = common()
    from dataclasses import asdict
    from sourcebastion.inventory.contract import Environment, Producer
    from sourcebastion.inventory.registry import REGISTRY_SHA256

    provenance["source_before"] = fixture_facts(fixture)
    provenance["monotonic"] = time.monotonic()
    provenance["boot_id"] = proc_value("/proc/sys/kernel/random/boot_id").strip()
    provenance["timens_offsets"] = proc_value("/proc/self/timens_offsets")
    producer = Producer(
        name="native-fixed-inventory-entrypoint", version="1",
        code_sha256=sha(render(provenance["bindings"]["package_payloads"])),
        registry_sha256=REGISTRY_SHA256, config_sha256=config.sha256,
    )
    record = dict(
        schema_version="sourcebastion.inventory-control/1", deadline_monotonic=0,
        source_sha256=sha(render({row["path"]: row for row in fixture["files"]})),
        producer=producer.model_dump(mode="json"), discovery=asdict(config),
        environment=Environment().model_dump(mode="json"),
        runtime=asdict(runtime), go_sha256=None,
    )
    assert len(render(record)) <= 65536
    save("control-recipe.json", record)
    save("image-preparation.json", provenance)


def verify():
    fixture, runtime, config, provenance = common()
    from sourcebastion.inventory.contract import Inventory, canonical_bytes
    from sourcebastion.inventory.cyclonedx import export
    from sourcebastion.inventory.matching import Consumer, recover

    before = json.loads(read(PROOF / "image-preparation.json", 131072))
    assert all(before[key] == value for key, value in provenance.items())
    assert fixture_facts(fixture) == before["source_before"]
    host = json.loads(read(PROOF / "host-observation.json", 65536))
    assert host["status"] == "child-exited-zero-and-owned-container-removed"
    assert host["entry_exit_code"] == 0 and host["container_remove_exit_code"] == 0
    record_raw = read(Path("/control/job.json"), 65536)
    record = json.loads(record_raw)
    assert sha(record_raw) == host["control_sha256"]
    assert host["absolute_deadline"] == record["deadline_monotonic"] == host["admission_started"] + 150
    assert before["boot_id"] == host["boot_id"] and before["timens_offsets"] == host["timens_offsets"]
    assert host["preparation_started"] <= before["monotonic"] <= host["preparation_finished"]
    raw = read(PROOF / "entrypoint.stdout", 65536)
    assert raw and not read(PROOF / "entrypoint.stderr", 65536)
    receipt = json.loads(raw)
    assert receipt["authority"] == "child-artifact-facts-only" and receipt["kernel_admission"] == "not_observed"
    assert receipt["schema_version"] == "sourcebastion.dependency-job/1" and receipt["reason"] is None
    assert set(receipt["stages"].values()) == {"succeeded"}
    assert receipt["execution"] == {"exit_code": 0, "lifecycle": "leader-reaped-only"}
    assert receipt["source_sha256"] == record["source_sha256"]
    assert receipt["producer"] == record["producer"] and receipt["discovery_config_sha256"] == config.sha256
    facts = receipt["artifacts"]
    assert len(facts) == len(NAMES) and {row["name"] for row in facts} == NAMES
    assert {path.name for path in OUTPUT.iterdir()} == NAMES
    artifacts = {}
    for fact in facts:
        content = read(OUTPUT / fact["name"], 64 * 1024**2)
        assert fact["bytes"] == len(content) and fact["sha256"] == sha(content)
        artifacts[fact["name"]] = content
    value = Inventory.model_validate_json(artifacts["inventory.json"])
    assert canonical_bytes(value) == artifacts["inventory.json"]
    assert value.producer.model_dump(mode="json") == record["producer"]
    assert value.source_sha256 == record["source_sha256"]
    assert len(value.occurrences) == 5 and not value.relationships and not value.roots and not value.installed_environments
    by_path = {row.source.path: row for row in value.occurrences}
    assert len(by_path) == 5
    expected_files = {row["path"]: row for row in fixture["files"]}
    required = {}
    for expected in fixture["expected"]["selected"]:
        observed = by_path[expected["path"]]
        assert observed.name == expected["name"] and observed.selected_version == expected["version"]
        assert observed.source.locator == "line:1" and observed.source.source_sha256 == expected_files[expected["path"]]["sha256"]
        assert observed.purl == "pkg:pypi/" + expected["name"] + "@" + expected["version"]
        assert observed.activation == expected["activation"] and observed.marker == expected.get("marker")
        assert [row.model_dump(mode="json") for row in observed.hashes] == expected["hashes"]
        assert observed.root_id is observed.installed_environment_id is None
        assert observed.directness == "unknown" and not observed.scopes
        required[observed.id] = expected["required_advisories"]
    expected_unselected, = fixture["expected"]["unselected"]
    unselected = by_path[expected_unselected["path"]]
    assert unselected.name == expected_unselected["name"]
    assert unselected.declared_range == expected_unselected["declared_range"]
    assert unselected.source.locator == "line:" + str(expected_unselected["line"])
    assert unselected.source.source_sha256 == expected_files[expected_unselected["path"]]["sha256"]
    assert unselected.selected_version is None and unselected.purl == "pkg:pypi/requests"
    assert unselected.marker is None and unselected.activation == "active" and not unselected.hashes
    assert unselected.root_id is unselected.installed_environment_id is None
    assert unselected.directness == "unknown" and not unselected.scopes
    assert unselected.id not in required
    post_deadline = time.monotonic() + 150

    def post_check():
        if time.monotonic() >= post_deadline:
            raise TimeoutError("finite-ci-post-verifier-deadline")

    artifact = export(value, deadline=post_deadline, check=post_check)
    assert artifact.content == artifacts["sbom.cdx.json"]
    consumer = Consumer.model_validate(receipt["consumer"])
    assert consumer.binary_sha256 == runtime.binary_sha256 and consumer.version == runtime.version
    assert consumer.advisory_snapshot_sha256 == runtime.advisory_sha256
    assert consumer.advisory_schema == runtime.advisory_schema and consumer.advisory_built == runtime.advisory_built
    assert consumer.config_sha256 == sha(artifacts["consumer-config.json"])
    configuration = json.loads(artifacts["consumer-config.json"])
    assert configuration["environment"]["GOMAXPROCS"] == "2"
    assert configuration["source_policy"] == "explicit-sbom-only"
    assert configuration["yaml_sha256"] == sha(artifacts["grype.yaml"])
    recovered = json.loads(artifacts["recovery.json"])
    replay = recover(value, artifact, artifacts["grype.json"], consumer=consumer, deadline=post_deadline, check=post_check)
    assert recovered["identity_sha256"] == replay.identity_sha256 == receipt["recovery_identity_sha256"]
    assert recovered["inventory_sha256"] == sha(artifacts["inventory.json"])
    assert recovered["sbom_sha256"] == sha(artifact.content)
    assert recovered["output_sha256"] == sha(artifacts["grype.json"])
    from dataclasses import asdict
    assert recovered["matches"] == [asdict(row) for row in replay.matches]
    assert recovered["occurrence_contexts"] == {identifier: json.loads(context) for identifier, context in replay.occurrence_contexts}
    assert recovered["occurrence_contexts"].keys() == required.keys()
    report = json.loads(artifacts["grype.json"])
    assert len(report["matches"]) == len(recovered["matches"]) >= 18
    helpers = runpy.run_path(str(WORK / "scripts/verify-inventory-real-grype.py"), run_name="reviewed_advisory_predicates")
    for identifier, groups in required.items():
        for group in groups:
            aliases = {(row["id"], row["namespace"]) for row in group}
            assert any(
                match["occurrence_id"] == identifier
                and helpers["known_advisory"](report["matches"][match["ordinal"]], aliases)
                for match in recovered["matches"]
            )
    proof = dict(
        status="native-installed-entrypoint-finite-passed", provenance=provenance,
        receipt_sha256=sha(raw), control_sha256=sha(record_raw),
        matches=len(report["matches"]), selected_ids=sorted(required),
        unselected_id=unselected.id, all_required_advisory_groups=True,
        host_observation_sha256=sha(read(PROOF / "host-observation.json", 65536)),
        scope="Actual installed -I -m entrypoint with original fixed fixture and explicit SBOM Grype/recovery. Finite child facts only; no kernel aggregate120CPU, peak metrics, all-descendant/parent-death/network-attempt/custody/route/negotiation/ingestion/release/wholeS04 acceptance",
    )
    save("proof.json", proof)
    print(json.dumps({key: proof[key] for key in ("status", "matches", "receipt_sha256")}))


if __name__ == "__main__":
    if sys.flags.optimize:
        raise RuntimeError("optimized-probe-runtime-refused")
    if len(sys.argv) != 2 or sys.argv[1] not in {"prepare", "verify"}:
        raise SystemExit("usage: verify-inventory-entrypoint.py prepare|verify")
    (prepare if sys.argv[1] == "prepare" else verify)()
