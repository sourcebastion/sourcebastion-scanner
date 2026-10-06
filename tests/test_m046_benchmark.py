import hashlib
import io
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import tarfile

import pytest

from evaluation.m046 import benchmark, container_job
from evaluation.m046.cgroup_metrics import cpu_set
from evaluation.m046 import prepare as preparation


@pytest.mark.parametrize("engines", [[], ["unknown"]])
def test_preparation_refuses_invalid_selection_before_side_effects(tmp_path, engines):
    destination = tmp_path / "tools"
    with pytest.raises(ValueError, match="selection"):
        preparation.prepare(destination, engines)
    assert not destination.exists()


def test_single_engine_preparation_never_builds_unselected_tools(tmp_path, monkeypatch):
    calls = []

    def download(url, destination, _checksum):
        calls.append(url)
        with tarfile.open(destination, "w:gz") as archive:
            content = b"synthetic selection test, never executed"
            member = tarfile.TarInfo("syft")
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))

    monkeypatch.setattr(preparation, "download", download)
    manifest = preparation.prepare(tmp_path / "tools", ["syft"])
    assert set(manifest["tools"]) == {"syft"}
    assert len(calls) == 1 and "/anchore/syft/" in calls[0]
    assert json.loads((tmp_path / "tools/manifest.json").read_text()) == manifest


def test_docker_proofs_refuse_disabled_assertions(tmp_path):
    output = tmp_path / "proofs"
    result = subprocess.run(
        [sys.executable, "-O", "-m", "evaluation.m046.docker_proofs", "--output", str(output)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0 and "optimized execution is refused" in result.stderr
    assert not output.exists()


def test_native_elf_accepts_local_interpreter():
    benchmark.native_elf(sys.executable)


@pytest.mark.parametrize(
    "header", [b"", b"#!/bin/sh\n", b"\x7fELF\x01\x01" + b"\0" * 14, b"\x7fELF\x02\x02" + b"\0" * 14]
)
def test_native_elf_refuses_non_native_headers(tmp_path, header):
    binary = tmp_path / "tool"
    binary.write_bytes(header)
    with pytest.raises(ValueError, match="native"):
        benchmark.native_elf(binary)


def test_native_elf_refuses_opposite_architecture(tmp_path):
    header = bytearray(b"\x7fELF\x02\x01" + b"\0" * 14)
    struct.pack_into("<H", header, 18, 183 if platform.machine() == "x86_64" else 62)
    binary = tmp_path / "tool"
    binary.write_bytes(header)
    with pytest.raises(ValueError, match="native"):
        benchmark.native_elf(binary)


def test_effective_cpu_set_expands_ranges():
    assert cpu_set("2-4,7,9-10\n") == {2, 3, 4, 7, 9, 10}


@pytest.mark.parametrize("controller,driver", [(151, 0.0005), (0.0005, 151), (151, 151)])
def test_wall_budget_refuses_either_clock_overrun(controller, driver):
    result = {"aggregate_cpu_seconds": 1, "wall_seconds": controller, "measured_job_wall_seconds": driver}
    metrics = {"peak_charged_memory_bytes": 1024, "oom_kills": 0}
    assert benchmark.budget_overruns(result, metrics, metrics) == ["wall"]


@pytest.fixture
def capture_paths(tmp_path, monkeypatch):
    work, output = tmp_path / "work", tmp_path / "private"
    work.mkdir()
    output.mkdir()
    monkeypatch.setattr(container_job, "WORK", work)
    monkeypatch.setattr(container_job, "OUTPUT", output)
    return work, output


def test_capture_checksum_binds_retained_bytes_and_permissions(capture_paths):
    work, output = capture_paths
    raw = b'{"synthetic":true}\n'
    (work / "raw.json").write_bytes(raw)
    previous = os.umask(0)
    try:
        result = container_job.capture_raw()
    finally:
        os.umask(previous)
    assert (output / "raw.json").read_bytes() == raw
    assert result["captured_raw_sha256"] == hashlib.sha256(raw).hexdigest()
    assert (output / "raw.json").stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize("kind", ["symlink", "fifo", "too-large", "parent-symlink"])
def test_capture_refuses_adversarial_results(capture_paths, kind):
    work, output = capture_paths
    private = output / "sentinel"
    private.write_bytes(b"synthetic-private")
    raw = work / "raw.json"
    if kind == "symlink":
        raw.symlink_to(private)
    elif kind == "fifo":
        os.mkfifo(raw)
    elif kind == "too-large":
        with raw.open("wb") as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
    else:
        target = work.with_name("replacement")
        work.rename(target)
        work.symlink_to(target, target_is_directory=True)
        (target / "raw.json").write_bytes(b"untrusted")
    with pytest.raises((OSError, ValueError)):
        container_job.capture_raw()
    assert not (output / "raw.json").exists()
    assert private.read_bytes() == b"synthetic-private"


def test_capture_refuses_replacement_during_read(capture_paths, monkeypatch):
    work, output = capture_paths
    raw = work / "raw.json"
    raw.write_bytes(b"initial")
    original = os.read
    replaced = False

    def replace(fd, amount):
        nonlocal replaced
        content = original(fd, amount)
        if not replaced:
            replaced = True
            other = work / "new"
            other.write_bytes(b"changed")
            other.replace(raw)
        return content

    monkeypatch.setattr(os, "read", replace)
    with pytest.raises(ValueError, match="changed"):
        container_job.capture_raw()
    assert not (output / "raw.json").exists()
