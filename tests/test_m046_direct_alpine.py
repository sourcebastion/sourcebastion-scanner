"""Finite runtime boundaries: exercised native closure and immutable job policy."""

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from evaluation.m046 import direct_alpine as alpine
from evaluation.m046.direct_alpine_guard import watch
from evaluation.m046.direct_alpine_probe import code_member, loaded_closure
from evaluation.m046.direct_job import candidate
from evaluation.m046.syft_control_audit import hash_records


def container(source):
    return {
        "Image": "sha256:" + "1" * 64,
        "Config": {
            "User": "65534:65534",
            "Entrypoint": ["/opt/m046/venv/bin/python"],
            "Cmd": ["-I", "-B", "/opt/m046/frontend/direct_alpine_probe.py"],
        },
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "Privileged": False,
            "Memory": 2 * 1024**3,
            "MemorySwap": 2 * 1024**3,
            "NanoCpus": 2_000_000_000,
            "PidsLimit": 32,
            "CapDrop": ["ALL"],
            "CapAdd": None,
            "SecurityOpt": ["no-new-privileges"],
        },
        "Mounts": [{"Type": "bind", "Source": str(source.resolve()), "Destination": "/source", "RW": False}],
    }


@pytest.mark.parametrize(
    "key,value",
    [
        ("NetworkMode", "bridge"),
        ("ReadonlyRootfs", False),
        ("Privileged", True),
        ("Memory", 0),
        ("MemorySwap", -1),
        ("NanoCpus", 0),
        ("PidsLimit", 0),
        ("CapDrop", []),
        ("CapAdd", ["SYS_ADMIN"]),
        ("SecurityOpt", []),
    ],
)
def test_actual_container_enforcement_mismatch_refuses_before_probe(tmp_path, key, value):
    record = container(tmp_path)
    alpine.verify_container(record, record["Image"], tmp_path)
    record["HostConfig"][key] = value
    with pytest.raises(ValueError, match="container boundary"):
        alpine.verify_container(record, record["Image"], tmp_path)


@pytest.mark.parametrize("changed", ["image", "user", "python", "source", "write", "extra-mount"])
def test_runtime_authority_and_source_binding_refuse_changes(tmp_path, changed):
    record = container(tmp_path)
    image = record["Image"]
    if changed == "image":
        record["Image"] = "mutable:latest"
    elif changed == "user":
        record["Config"]["User"] = "root"
    elif changed == "python":
        record["Config"]["Entrypoint"] = ["/usr/bin/python"]
    elif changed == "source":
        record["Mounts"][0]["Source"] += "-changed"
    elif changed == "write":
        record["Mounts"][0]["RW"] = True
    else:
        record["Mounts"].append(deepcopy(record["Mounts"][0]))
    with pytest.raises(ValueError, match="container boundary"):
        alpine.verify_container(record, image, tmp_path)


def probe(tmp_path):
    for name, content in alpine.FILES.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    provenance = {key: "a" * 64 for key in ("code_sha256", "registry_sha256", "config_sha256")}
    provenance.update(producer="fixture", environment_policy="unknown")
    content, status = candidate("direct-cyclonedx", tmp_path, provenance)
    assert status == 0
    packages = {
        name: {"version": version, "sources": {"module.py": "a" * 64}} for name, version in alpine.VERSIONS.items()
    }
    packages["rpds-py"]["sources"] = {"rpds/rpds.cpython-314.so": "b" * 64, "rpds_py.libs/libgcc_s.so.1": "c" * 64}
    libraries = {
        "/opt/m046/venv/lib/python3.14/site-packages/" + name: sha
        for name, sha in packages["rpds-py"]["sources"].items()
    }
    observed = {
        "status": "finite-import-export-only",
        "python": "3.14.8",
        "architecture": "x86_64",
        "executable": "/opt/m046/venv/bin/python",
        "prefix": "/opt/m046/venv",
        "isolated": 1,
        "uid": 65534,
        "gid": 65534,
        "os_release": "ID=alpine\nVERSION_ID=3.23.6\n",
        "packages": packages,
        "frontend": {"probe.py": "d" * 64},
        "full_contract_qualified": False,
        "loaded_libraries": libraries,
        "sbom": json.loads(content),
    }
    oracle = {
        "spec": {"kind": "pins", "count": 2},
        "files": {
            name: {"sha256": alpine.hashlib.sha256(content.encode()).hexdigest()}
            for name, content in alpine.FILES.items()
        },
        "expected": {
            "identities": 1,
            "occurrences": 2,
            "identities_sha256": hash_records({"pypi:pip@26.0.1"}),
            "occurrences_sha256": hash_records([("a", "pypi:pip@26.0.1"), ("b", "pypi:pip@26.0.1")]),
        },
    }
    return observed, deepcopy(packages), deepcopy(observed["frontend"]), oracle


def test_actual_export_preserves_two_roots_and_requires_exercised_native_bytes(tmp_path):
    observed, packages, frontend, oracle = probe(tmp_path)
    result = alpine.verify_probe(observed, packages, frontend, "amd64", oracle)
    assert result["occurrences"] == 2 and result["identities"] == 1
    vendor = next(name for name in observed["loaded_libraries"] if name.endswith(".so.1"))
    observed["loaded_libraries"][vendor] = "f" * 64
    with pytest.raises(ValueError, match="not loaded with expected identity"):
        alpine.verify_probe(observed, packages, frontend, "amd64", oracle)


@pytest.mark.parametrize("change", ["missing-library", "wheel", "frontend", "python", "wrong-root"])
def test_runtime_or_native_closure_or_source_mismatch_cannot_pass(tmp_path, change):
    observed, packages, frontend, oracle = probe(tmp_path)
    if change == "missing-library":
        observed["loaded_libraries"].pop(next(iter(observed["loaded_libraries"])))
    elif change == "wheel":
        observed["packages"]["rpds-py"]["sources"]["rpds/rpds.cpython-314.so"] = "f" * 64
    elif change == "frontend":
        observed["frontend"]["probe.py"] = "f" * 64
    elif change == "python":
        observed["python"] = "3.13.5"
    else:
        oracle["files"]["a/requirements.txt"]["sha256"] = "f" * 64
    with pytest.raises(ValueError):
        alpine.verify_probe(observed, packages, frontend, "amd64", oracle)


def test_shared_library_suffixes_and_loaded_map_paths_are_bound(tmp_path):
    native = tmp_path / "libgcc_s.so.1"
    native.write_bytes(b"native bytes")
    alias = tmp_path / "alias.so.1"
    alias.symlink_to(native)
    maps = f"1-2 r-xp 0 00:00 1 {alias}\n2-3 r--p 0 00:00 1 {alias}\n"
    assert loaded_closure(maps) == {str(alias): alpine.digest(native)}
    assert code_member(Path("rpds_py.libs/libgcc_s-abc.so.1"))
    assert not code_member(Path("LICENSE"))
    with pytest.raises(ValueError, match="uncertain loaded"):
        loaded_closure(maps.replace(str(alias), str(alias) + " (deleted)"))


def test_driver_capture_is_bounded_and_timeout_is_visible(tmp_path):
    with pytest.raises(subprocess.TimeoutExpired):
        alpine.checked([sys.executable, "-c", "import time; time.sleep(10)"], tmp_path, "timeout", 0.1)
    assert (tmp_path / "timeout.stdout").exists()
    assert (tmp_path / "timeout.stderr").exists()


def fake_docker(tmp_path):
    script = tmp_path / "fake-docker.py"
    script.write_text(
        "import pathlib,sys\n"
        f"state=pathlib.Path({str(tmp_path / 'active')!r})\n"
        "if state.exists():\n state.unlink(); print('1'*64)\n"
        "else:\n print('No such container: '+sys.argv[-1],file=sys.stderr);sys.exit(1)\n"
    )
    (tmp_path / "active").write_text("running")
    return script


def test_watchdog_survives_controller_sigkill_and_cleans_owned_job(tmp_path):
    script = fake_docker(tmp_path)
    receipt = tmp_path / "receipt.json"
    name = "m046-direct-alpine-" + "a" * 32
    controller = (
        "import os,subprocess,sys,time; from pathlib import Path; "
        "r,w=os.pipe(); "
        f"code={('from pathlib import Path; from evaluation.m046.direct_alpine_guard import watch; raise SystemExit(watch(int(__import__("sys").argv[1]),' + repr(name) + ',Path(' + repr(str(receipt)) + '),docker=[' + repr(sys.executable) + ',' + repr(str(script)) + '],seconds=5,grace=.2))')!r}; "
        "p=subprocess.Popen([sys.executable,'-B','-c',code,str(r)],pass_fds=(r,),start_new_session=True); "
        "os.close(r); "
        f"Path({str(tmp_path / 'ready')!r}).write_text(str(p.pid)); time.sleep(10)"
    )
    process = subprocess.Popen([sys.executable, "-B", "-c", controller])
    deadline = time.monotonic() + 5
    try:
        while not (tmp_path / "ready").exists():
            assert time.monotonic() < deadline
            time.sleep(0.01)
        process.kill()
        process.wait(timeout=2)
        while not receipt.exists():
            assert time.monotonic() < deadline
            time.sleep(0.01)
        result = json.loads(receipt.read_text())
        assert result["reason"] == "controller-disconnected"
        assert result["cleanup_confirmed"] is True
        assert result["container_name"] == name
        assert not (tmp_path / "active").exists()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)


def test_watchdog_deadline_and_normal_cid_receipt_are_distinct(tmp_path):
    script = fake_docker(tmp_path)
    name = "m046-direct-alpine-" + "b" * 32
    cidfile = tmp_path / "cid"
    cidfile.write_text("1" * 64 + "\n")
    for reason, done in (("deadline", False), ("controller-completed", True)):
        read_fd, write_fd = os.pipe()
        if done:
            os.write(write_fd, b"D")
        receipt = tmp_path / (reason + ".json")
        try:
            assert (
                watch(
                    read_fd, name, receipt, docker=[sys.executable, str(script)], seconds=0.05, grace=0, cidfile=cidfile
                )
                == 0
            )
        finally:
            os.close(write_fd)
        result = json.loads(receipt.read_text())
        assert result["reason"] == reason
        assert result["known_container_ids"] == ["1" * 64]
        assert result["cleanup_confirmed"] is True


def test_watchdog_cannot_promote_uncertain_cleanup(tmp_path):
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"D")
    receipt = tmp_path / "receipt.json"
    try:
        status = watch(
            read_fd,
            "m046-direct-alpine-" + "c" * 32,
            receipt,
            docker=[sys.executable, "-c", "raise SystemExit(2)"],
            grace=0,
        )
    finally:
        os.close(write_fd)
    assert status == 2
    assert json.loads(receipt.read_text())["cleanup_confirmed"] is False


def test_uncertain_cid_still_cleans_name_and_refuses_success(tmp_path):
    script = fake_docker(tmp_path)
    cidfile = tmp_path / "cid"
    cidfile.write_text("")
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"D")
    receipt = tmp_path / "receipt.json"
    try:
        status = watch(
            read_fd,
            "m046-direct-alpine-" + "d" * 32,
            receipt,
            docker=[sys.executable, str(script)],
            grace=0,
            cidfile=cidfile,
        )
    finally:
        os.close(write_fd)
    result = json.loads(receipt.read_text())
    assert status == 2 and result["cid_errors"]
    assert result["cleanup_confirmed"] is False
    assert not (tmp_path / "active").exists()
