"""Upgrade and release gates fail on actual semantic or evidence regressions."""

from copy import deepcopy
import gzip
import hashlib
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tarfile
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
upgrade = runpy.run_path(str(ROOT / "scripts/inventory_upgrade.py"))
release = runpy.run_path(str(ROOT / "scripts/inventory_release.py"))


@pytest.fixture
def pair():
    oracle = json.loads((ROOT / "evaluation/m046/canonical-source-expectations-v1.json").read_text())
    proof = {"schema_version": "m046.canonical-source-expectations-proof/1",
             "historical_oracle_sha256": oracle["historical_oracle_sha256"],
             "cases": [{"case": row["case"], "observed": deepcopy(row)} for row in oracle["cases"]]}
    return oracle, proof


def test_all_64_independent_cases_compare_and_generated_ids_do_not_define_parity(pair):
    old, new = pair
    result = upgrade["corpus_diff"](old, new)
    assert result["status"] == "passed" and result["cases_compared"] == 64
    row = next(row for row in new["cases"] if row["observed"]["records"]["occurrences"])
    value = row["observed"]
    aliases = {record["id"]: "new:" + record["id"] for records in value["records"].values() for record in records}
    helper = runpy.run_path(str(ROOT / "scripts/verify-inventory-expectations.py"))
    for collection, records in value["records"].items():
        value["records"][collection] = [helper["normalize"](record, aliases) for record in records]
    value["coverage"]["inputs"] = [helper["normalize"](record, aliases) for record in value["coverage"]["inputs"]]
    assert upgrade["corpus_diff"](old, new)["status"] == "passed"


def test_custom_input_disappearing_fails_even_if_the_oracle_is_edited(pair):
    old, new = pair
    row = next(row for row in new["cases"] if any(
        record["source"]["path"] == "scripts/python-build.in" for record in row["observed"]["records"]["occurrences"]
    ))
    # Removing the whole case cannot be hidden by lowering the expected count.
    new["cases"].remove(row)
    result = upgrade["corpus_diff"](old, new)
    assert result["status"] == "review-required"
    assert row["case"] in result["missing_cases"]


@pytest.mark.parametrize("dimension", ["packages", "versions", "edges", "coverage", "context"])
def test_full_semantic_dimensions_produce_reviewable_diffs(pair, dimension):
    old, new = pair
    if dimension == "edges":
        row = next(row for row in new["cases"] if row["observed"]["records"]["relationships"])
        row["observed"]["records"]["relationships"][0]["evidence_status"] = "unassessed"
    elif dimension == "context":
        row = next(row for row in new["cases"] if row["observed"]["records"]["applications"])
        row["observed"]["records"]["applications"][0]["version"] = "9.9.9"
    elif dimension == "coverage":
        row = new["cases"][0]
        row["observed"]["coverage"]["enumeration"] = "partial"
    else:
        row = next(row for row in new["cases"] if row["observed"]["records"]["occurrences"])
        record = row["observed"]["records"]["occurrences"][0]
        record["name" if dimension == "packages" else "selected_version"] = "changed"
    result = upgrade["corpus_diff"](old, new)
    assert result["status"] == "review-required"
    assert dimension in next(change for change in result["changes"] if change["case"] == row["case"])["dimensions"]


def test_duplicate_case_and_ambiguous_source_are_refused(pair):
    old, new = pair
    new["cases"].append(deepcopy(new["cases"][0]))
    with pytest.raises(ValueError, match="duplicate"):
        upgrade["corpus_diff"](old, new)


def test_finding_changes_and_duplicate_match_loss_are_reported():
    one = {"vulnerability": {"id": "CVE-2026-1234", "severity": "High"}, "artifact": {"purl": "pkg:pypi/pip@26.0.1"}}
    result = upgrade["finding_diff"]({"matches": [one, one]}, {"matches": [one]},
                                     baseline_snapshot="a" * 64, candidate_snapshot="a" * 64)
    assert result["status"] == "review-required" and result["removed"] == [one]
    with pytest.raises(ValueError, match="snapshot-changed"):
        upgrade["finding_diff"]({"matches": []}, {"matches": []}, baseline_snapshot="a" * 64, candidate_snapshot="b" * 64)
    with pytest.raises(ValueError, match="incomplete"):
        upgrade["finding_diff"]({}, {"matches": []}, baseline_snapshot="a" * 64, candidate_snapshot="a" * 64)


def test_cli_retains_failed_diff_and_exits_nonzero(pair, tmp_path):
    old, new = pair
    new["cases"].pop()
    for name, value in (("old", old), ("new", new)):
        (tmp_path / name).write_text(json.dumps(value))
    output = tmp_path / "diff.json"
    result = subprocess.run([sys.executable, str(ROOT / "scripts/verify-inventory-upgrade.py"),
                             "--baseline", str(tmp_path / "old"), "--candidate", str(tmp_path / "new"),
                             "--output", str(output)], capture_output=True)
    assert result.returncode == 1
    assert json.loads(output.read_text())["corpus"]["missing_cases"]


def resource_record():
    return {"observer": "host-cgroup-v2", "architecture": "arm64", "cpu_usec": 100,
            "memory_peak": 1000, "swap_peak": 0, "pids_peak": 3, "wall_seconds": 1.0,
            "oom_kill": 0, "exit_code": 0, "removed": True}


@pytest.mark.parametrize("field,value", [("cpu_usec", 120000001), ("memory_peak", 2147483649),
    ("swap_peak", 1), ("pids_peak", 257), ("wall_seconds", 150.01), ("wall_seconds", float("nan")),
    ("cpu_usec", True), ("exit_code", 2), ("removed", False), ("observer", "child-json"), ("oom_kill", 1)])
def test_resource_gate_refuses_excess_missing_authority_and_cleanup_failure(field, value):
    row = resource_record()
    row[field] = value
    with pytest.raises(ValueError):
        release["measured_resources"](row)


def test_resource_gate_accepts_exact_ceilings():
    row = resource_record()
    row.update(cpu_usec=120000000, memory_peak=2147483648, pids_peak=256, wall_seconds=150)
    assert release["measured_resources"](row) == row


def oci(tmp_path, *, corrupt=False):
    blobs = {}
    def descriptor(raw, media_type):
        digest = hashlib.sha256(raw).hexdigest()
        blobs["blobs/sha256/" + digest] = raw
        return {"digest": "sha256:" + digest, "size": len(raw), "mediaType": media_type}
    layer = descriptor(gzip.compress(b"verified compressed layer"), "application/vnd.oci.image.layer.v1.tar+gzip")
    config = descriptor(json.dumps({"os": "linux", "architecture": "arm64", "rootfs": {
        "type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(b"verified compressed layer").hexdigest()]
    }}).encode(), "application/vnd.oci.image.config.v1+json")
    manifest = descriptor(json.dumps({"schemaVersion": 2, "config": config, "layers": [layer]}).encode(), "application/vnd.oci.image.manifest.v1+json")
    blobs["index.json"] = json.dumps({"schemaVersion": 2, "manifests": [manifest]}).encode()
    if corrupt:
        blobs["blobs/sha256/" + layer["digest"][7:]] = b"x" * layer["size"]
    path = tmp_path / "oci.tar"
    with tarfile.open(path, "w") as archive:
        for name, raw in blobs.items():
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return path


def test_oci_growth_uses_verified_compressed_bytes_and_native_architecture(tmp_path):
    layers = release["oci_layers"](oci(tmp_path), "arm64")
    assert release["growth"](layers, layers)["added_compressed_bytes"] == 0
    with pytest.raises(ValueError, match="architecture"):
        release["oci_layers"](tmp_path / "oci.tar", "amd64")
    empty = {**layers, "layers": []}
    assert release["growth"](empty, layers)["added_compressed_bytes"] == layers["layers"][0]["size"]
    oversized = {**layers, "layers": [{"digest": "new", "size": 262144001}]}
    with pytest.raises(ValueError, match="ceiling"):
        release["growth"](empty, oversized)


def test_oci_digest_tampering_is_refused(tmp_path):
    with pytest.raises(ValueError, match="digest-mismatch"):
        release["oci_layers"](oci(tmp_path, corrupt=True), "arm64")


@pytest.mark.parametrize("same_image", [True, False])
def test_compressed_growth_cli_binds_the_actual_tested_image(tmp_path, same_image):
    path = oci(tmp_path)
    value = release["oci_layers"](path, "arm64")
    inspect = tmp_path / "image.json"
    inspect.write_text(json.dumps({"Id": value["config_digest"] if same_image else "sha256:" + "b" * 64,
                                   "Architecture": "arm64", "Os": "linux"}))
    output = tmp_path / "growth.json"
    result = subprocess.run([sys.executable, str(ROOT / "scripts/verify-inventory-release-size.py"),
                             "--baseline", str(path), "--candidate", str(path), "--architecture", "arm64",
                             "--candidate-image", str(inspect), "--output", str(output)], capture_output=True)
    assert result.returncode == (0 if same_image else 1)
    receipt = json.loads(output.read_text())
    assert receipt["status"] == ("passed" if same_image else "failed")
    if not same_image:
        assert receipt["reason"] == "compressed-candidate-is-not-tested-image"


def test_download_hash_failure_never_succeeds(tmp_path, monkeypatch):
    tool = runpy.run_path(str(ROOT / "scripts/prepare-inventory-node.py"))
    function = tool["prepare"]
    monkeypatch.setitem(function.__globals__, "urlopen", lambda *_args, **_kwargs: io.BytesIO(b"wrong APK"))
    monkeypatch.setattr(function.__globals__["platform"], "machine", lambda: "x86_64")
    with pytest.raises(ValueError, match="digest-mismatch"):
        function(ROOT / ".github/inventory-runtime-pins.json", tmp_path / "downloads")


def test_offline_packaging_reads_installed_apk_data_without_repository_queries():
    functions = runpy.run_path(str(ROOT / "scripts/verify-inventory-packaging.py"))
    raw = b"C:checksum\nP:nodejs\nV:24.18.1-r0\nA:aarch64\nF:usr/bin\nR:node\n\nP:npm\nV:11.11.0-r0\n"
    assert functions["installed_apks"](raw) == {"nodejs": "24.18.1-r0", "npm": "11.11.0-r0"}
    for refused in (b"", b"P:nodejs\n", raw + b"\nP:nodejs\nV:24.18.1-r0\n", b"P:nodejs\nP:npm\nV:1\n"):
        with pytest.raises(ValueError):
            functions["installed_apks"](refused)


@pytest.mark.parametrize("failure", ["cpu", "create-timeout", "cleanup"])
def test_resource_driver_removes_only_owned_container_on_failure(tmp_path, monkeypatch, failure):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    functions = runpy.run_path(str(ROOT / "scripts/run-inventory-resource-proof.py"))
    execute = functions["run"]
    scope = execute.__globals__
    monkeypatch.setattr(scope["platform"], "system", lambda: "Linux")
    monkeypatch.setattr(scope["platform"], "machine", lambda: "aarch64")
    cid, image = "c" * 64, "sha256:" + "a" * 64
    calls = []
    def docker(*args, **_kwargs):
        calls.append(args)
        if args[:2] == ("image", "inspect"):
            return json.dumps([{"Id": image, "Architecture": "arm64", "Os": "linux"}]).encode()
        if args[0] == "create":
            Path(args[args.index("--cidfile") + 1]).write_text(cid)
            if failure == "create-timeout":
                raise TimeoutError()
        if args[0] == "inspect":
            return json.dumps([{"Image": image, "State": {"Running": True, "Pid": 123}}]).encode()
        if args[0] == "rm" and failure == "cleanup":
            raise OSError()
        return b""
    monkeypatch.setitem(scope, "docker", docker)
    monkeypatch.setitem(scope, "cgroup", lambda _pid: tmp_path / "cgroup")
    monkeypatch.setitem(scope, "limits", lambda _root: None)
    sample = {key: resource_record()[key] for key in ("cpu_usec", "memory_peak", "swap_peak", "pids_peak", "oom_kill")}
    values = iter([sample, {**sample, "cpu_usec": 120000001}])
    monkeypatch.setitem(scope, "observe", lambda _root: next(values))
    original_read = scope["read"]
    monkeypatch.setitem(scope, "read", lambda path: ("124" if str(path).endswith("/children") else "State:\tT") if str(path).startswith("/proc/") else original_read(path))
    args = SimpleNamespace(image="example", output=tmp_path / "proof", checkout=ROOT,
                           provider=None, workload="stress", arm="flat-1000")
    assert execute(args) == 1
    removals = [args for args in calls if args[0] == "rm"]
    assert removals == [("rm", "--force", cid)]
    receipt = json.loads((args.output / "resources.json").read_text())
    assert receipt["status"] == "failed" and receipt["removed"] == (failure != "cleanup")


def _driver(tmp_path, monkeypatch, *, logs_bytes=b'{"ok": true}\n', logs_returncode=0, wait_code=0, delayed_stop=False):
    """Drive the resource proof to the output-capture step with a stub Docker."""
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    functions = runpy.run_path(str(ROOT / "scripts/run-inventory-resource-proof.py"))
    execute = functions["run"]
    scope = execute.__globals__
    args_holder = {}
    phase = {"continues": 0, "stopped": False, "second_reads": 0}
    monkeypatch.setattr(scope["platform"], "system", lambda: "Linux")
    monkeypatch.setattr(scope["platform"], "machine", lambda: "x86_64")
    cid, image = "c" * 64, "sha256:" + "a" * 64

    def docker(*args, **_kwargs):
        if args[:2] == ("image", "inspect"):
            return json.dumps([{"Id": image, "Architecture": "amd64", "Os": "linux"}]).encode()
        if args[0] == "create":
            Path(args[args.index("--cidfile") + 1]).write_text(cid)
        if args[0] == "inspect":
            return json.dumps([{"Image": image, "State": {"Running": True, "Pid": 123}}]).encode()
        if args[:3] == ("kill", "--signal", "CONT"):
            phase["continues"] += 1
            if delayed_stop and phase["continues"] == 2:
                assert phase["stopped"], "CONT before second STOP loses the wakeup"
        if args[0] == "wait":
            # The wrapper exits with the workload's status; the gate file in
            # this harness says 0, so the container must agree.
            return str(wait_code).encode()
        return b""

    class Logs:
        """Stands in for `docker logs`, writing exactly what the test chose."""

        returncode = logs_returncode

        def __init__(self, _command, stdout=None, stderr=None):
            stdout.write(logs_bytes)
            stdout.flush()

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            pass

    monkeypatch.setitem(scope, "docker", docker)
    monkeypatch.setitem(scope, "cgroup", lambda _pid: tmp_path / "cgroup")
    monkeypatch.setitem(scope, "limits", lambda _root: None)
    monkeypatch.setattr(scope["subprocess"], "Popen", Logs)
    sample = {key: resource_record()[key] for key in ("cpu_usec", "memory_peak", "swap_peak", "pids_peak", "oom_kill")}
    seen = []

    def observe(_root):
        if delayed_stop and seen:
            assert phase["stopped"], "final counters must be sampled while held"
        assert phase["continues"] < 2, "cgroup may be gone after release"
        # The pre-work call writes the gate file, standing in for a container
        # that has already finished, so the wait loop's /proc inspection (which
        # cannot be stubbed on a non-Linux host) is never reached. The loop
        # itself is covered by the cpu-ceiling test above.
        seen.append(1)
        if len(seen) >= 1:
            gate = args_holder["args"].output / "gate"
            if not (gate / "exit").exists():
                (gate / "exit").write_text("0")
        return dict(sample)

    monkeypatch.setitem(scope, "observe", observe)
    original_read = scope["read"]

    def read(path):
        text = str(path)
        if text.startswith("/proc/"):
            if text.endswith("/children"):
                return "124"
            if delayed_stop and phase["continues"] == 1:
                phase["second_reads"] += 1
                phase["stopped"] = phase["second_reads"] >= 3
                return "State:\tT" if phase["stopped"] else "State:\tR"
            return "State:\tT"
        if text.endswith("/gate/exit"):
            if delayed_stop:
                assert phase["stopped"], "exit file can still be empty before STOP"
            return "0"
        return original_read(path)

    monkeypatch.setitem(scope, "read", read)
    args = SimpleNamespace(image="example", output=tmp_path / "proof", checkout=ROOT,
                           provider=None, workload="stress", arm="flat-1000")
    args_holder["args"] = args
    return execute, args


def test_a_workload_that_produced_no_output_is_not_a_passed_resource_proof(tmp_path, monkeypatch):
    """A clean cgroup measurement of a workload that emitted nothing attests
    nothing. Observed in native CI: the receipt recorded `status: passed` with
    `workload_sha256` set to the digest of the empty string, and the failure
    only surfaced three layers downstream in the entrypoint verifier."""
    execute, args = _driver(tmp_path, monkeypatch, logs_bytes=b"")

    assert execute(args) == 1
    receipt = json.loads((args.output / "resources.json").read_text())
    assert receipt["status"] == "failed"
    assert receipt["reason"] == "resource-workload-output-empty"
    assert "workload_sha256" not in receipt, "no digest of nothing may be retained as evidence"


def test_a_container_exit_disagreeing_with_the_workload_is_refused(tmp_path, monkeypatch):
    """The wrapper exits with the workload's status, so a container status
    that differs means the lifecycle is not what the receipt describes."""
    execute, args = _driver(tmp_path, monkeypatch, wait_code=137)

    assert execute(args) == 1
    receipt = json.loads((args.output / "resources.json").read_text())
    assert receipt["reason"] == "resource-container-exit-disagrees-with-workload"


def test_a_workload_that_produced_output_still_passes(tmp_path, monkeypatch):
    """Guards the test above: the refusal must be about emptiness, not about
    the stubbed driver failing for some other reason."""
    execute, args = _driver(tmp_path, monkeypatch, logs_bytes=b'{"arm": "flat-1000"}\n')

    assert execute(args) == 0
    receipt = json.loads((args.output / "resources.json").read_text())
    assert receipt["status"] == "passed"
    assert receipt["workload_sha256"] == hashlib.sha256(b'{"arm": "flat-1000"}\n').hexdigest()


def test_exit_file_visibility_does_not_release_shell_before_second_stop(tmp_path, monkeypatch):
    execute, args = _driver(tmp_path, monkeypatch, delayed_stop=True)
    assert execute(args) == 0
    assert json.loads((args.output / "resources.json").read_text())["status"] == "passed"


@pytest.mark.parametrize("raw", [b"warning\n0", b"", b"0\n1"])
def test_ambiguous_docker_wait_output_is_refused(raw, monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    functions = runpy.run_path(str(ROOT / "scripts/run-inventory-resource-proof.py"))
    with pytest.raises(ValueError, match="exit-unreadable"):
        functions["read_bytes"](raw)
