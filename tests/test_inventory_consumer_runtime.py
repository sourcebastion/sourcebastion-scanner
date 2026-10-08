"""Finite held-file admission/refusal tests, no real Grype execution."""

from dataclasses import replace
import hashlib
import json
import os

import pytest

from sourcebastion.inventory import consumer_runtime as runtime
from sourcebastion.inventory.inputs import InputRefusal


def prepared(tmp_path, monkeypatch):
    binary = tmp_path / "grype"
    binary.write_bytes(b"\x7fELFfinite-not-executed")
    binary.chmod(0o500)
    root = tmp_path / "advisories"
    root.mkdir(mode=0o700)
    (root / "6").mkdir(mode=0o700)
    files = {
        "snapshot.json": json.dumps(
            {"database": {"valid": True, "schemaVersion": "v6.1.10", "built": "2026-10-06T06:32:14Z"}}
        ).encode(),
        "6/vulnerability.db": b"finite-source-authored-database-placeholder",
    }
    for name, raw in files.items():
        (root / name).write_bytes(raw)
        (root / name).chmod(0o400)
    monkeypatch.setattr(runtime, "BINARY", binary)
    monkeypatch.setattr(runtime, "ADVISORIES", root)
    spec = runtime.RuntimeSpec(
        hashlib.sha256(binary.read_bytes()).hexdigest(),
        binary.stat().st_size,
        tuple((name, hashlib.sha256(raw).hexdigest(), len(raw)) for name, raw in sorted(files.items())),
        "v6.1.10",
        "2026-10-06T06:32:14Z",
    )
    return spec, binary, root


def test_holds_native_binary_and_exact_advisory_bytes_then_closes_every_fd(tmp_path, monkeypatch):
    spec, binary, root = prepared(tmp_path, monkeypatch)
    checks = []
    with runtime.RuntimeBinding(spec, check=lambda: checks.append(True)) as binding:
        assert os.pread(binding.binary, 4, 0) == b"\x7fELF"
        assert binding.read_snapshot() == (root / "snapshot.json").read_bytes()
        assert len(binding.files) == 2 and len(binding.directories) == 2
        binding.validate()
        descriptors = [
            binding.binary,
            *[row[0] for row in binding.files.values()],
            *[row[0] for row in binding.directories.values()],
        ]
    assert len(checks) > 20
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.parametrize(
    "mutation", ["binary-content", "advisory-content", "extra", "root-replacement", "binary-replacement"]
)
def test_post_admission_change_stays_refused_after_restoration(tmp_path, monkeypatch, mutation):
    spec, binary, root = prepared(tmp_path, monkeypatch)
    with runtime.RuntimeBinding(spec, check=lambda: None) as binding:
        if mutation == "binary-content":
            binary.chmod(0o700)
            binary.write_bytes(b"\x7fELF" + b"x" * (spec.binary_bytes - 4))
        elif mutation == "advisory-content":
            (root / "6/vulnerability.db").chmod(0o600)
            (root / "6/vulnerability.db").write_bytes(b"changed")
        elif mutation == "extra":
            (root / "unexpected").write_bytes(b"no")
        elif mutation == "root-replacement":
            root.rename(tmp_path / "old-advisories")
            root.mkdir(mode=0o700)
        else:
            binary.rename(tmp_path / "old-grype")
            binary.write_bytes(b"\x7fELFfinite-not-executed")
            binary.chmod(0o500)
        with pytest.raises(InputRefusal):
            binding.validate()
        refusal = binding.refusal
        assert refusal
        with pytest.raises(InputRefusal) as error:
            binding.validate()
        assert error.value.reason == refusal


@pytest.mark.parametrize(
    "mutation", ["fifo", "symlink", "hardlink", "wrong-digest", "writable-directory", "unknown-file"]
)
def test_unsafe_initial_runtime_refused_without_blocking(tmp_path, monkeypatch, mutation):
    spec, binary, root = prepared(tmp_path, monkeypatch)
    if mutation == "fifo":
        binary.unlink()
        os.mkfifo(binary)
    elif mutation == "symlink":
        binary.rename(tmp_path / "real")
        binary.symlink_to(tmp_path / "real")
    elif mutation == "hardlink":
        os.link(root / "6/vulnerability.db", tmp_path / "alias")
    elif mutation == "wrong-digest":
        spec = replace(spec, binary_sha256="a" * 64)
    elif mutation == "writable-directory":
        (root / "6").chmod(0o777)
    else:
        (root / "unapproved").write_bytes(b"ignored-is-not-allowed")
    before = set(os.listdir("/proc/self/fd"))
    with pytest.raises((InputRefusal, OSError)):
        runtime.RuntimeBinding(spec, check=lambda: None)
    assert set(os.listdir("/proc/self/fd")) == before


def test_initial_and_final_hashing_uses_same_cancellation_and_budget_callback(tmp_path, monkeypatch):
    spec, binary, root = prepared(tmp_path, monkeypatch)
    refused = False

    def check():
        if refused:
            raise InputRefusal("test-shared-ledger-refused")

    with runtime.RuntimeBinding(spec, check=check) as binding:
        refused = True
        with pytest.raises(InputRefusal, match="test-shared-ledger-refused"):
            binding.validate()
        refused = False
        with pytest.raises(InputRefusal, match="test-shared-ledger-refused"):
            binding.validate()


@pytest.mark.parametrize(
    "name", ["../escape", "/absolute", "6//empty", "6/./dot", "6/../up", "six\\escape", "nul\x00file"]
)
def test_preparation_manifest_refuses_unsafe_paths(tmp_path, monkeypatch, name):
    spec, _binary, _root = prepared(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        replace(spec, advisory_files=spec.advisory_files + ((name, "a" * 64, 1),))


def test_snapshot_read_refusal_stays_sticky_and_closed_reads_are_refused(tmp_path, monkeypatch):
    spec, _binary, root = prepared(tmp_path, monkeypatch)
    binding = runtime.RuntimeBinding(spec, check=lambda: None)
    original = (root / "snapshot.json").read_bytes()
    (root / "snapshot.json").chmod(0o600)
    (root / "snapshot.json").write_bytes(b"x" * len(original))
    with pytest.raises(InputRefusal):
        binding.read_snapshot()
    (root / "snapshot.json").write_bytes(original)
    with pytest.raises(InputRefusal):
        binding.read_snapshot()
    binding.close()
    with pytest.raises(InputRefusal):
        binding.read_snapshot()
