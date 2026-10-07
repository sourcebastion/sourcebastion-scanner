"""Trusted Go preparation refusals; synthetic ELF is never executed."""

import hashlib
import json
import os
from pathlib import Path
import platform
import runpy

import pytest

PROBE = runpy.run_path(str(Path(__file__).parents[1] / "scripts/verify-inventory-expectations.py"))


@pytest.fixture
def preparation(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    source = tmp_path / "cmd/inventory-provider"
    source.mkdir(parents=True)
    for name in PROBE["GO_SOURCE_FILES"]:
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"synthetic reviewed source\n")
    pins = {"version": "test-version", f"linux_{architecture}_sha256": "a" * 64}
    (source / "toolchain.json").write_text(json.dumps(pins))
    binary = tmp_path / "synthetic-go-helper"
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[18:20] = {"amd64": 62, "arm64": 183}[architecture].to_bytes(2, "little")
    binary.write_bytes(header)
    binary.chmod(0o700)
    manifest = {
        "schema_version": "sourcebastion.provider-preparation/1",
        "status": "trusted-preparation-only",
        "architecture": architecture,
        "cgo_enabled": "0",
        "go_version": pins["version"],
        "go_archive_sha256": "a" * 64,
        "source_files": {name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in PROBE["GO_SOURCE_FILES"]},
        "go_source_binary_sha256": hashlib.sha256(header).hexdigest(),
        "go_source_binary_bytes": len(header),
    }
    receipt = tmp_path / "manifest.json"
    receipt.write_text(json.dumps(manifest))
    return binary, receipt, manifest


@pytest.mark.parametrize("change", ["schema", "status", "architecture", "cgo", "compiler", "archive", "digest", "size", "extra-source", "missing-source"])
def test_unbound_preparation_refuses_before_any_helper_execution(preparation, change):
    binary, receipt, manifest = preparation
    key = {"schema": "schema_version", "status": "status", "architecture": "architecture", "cgo": "cgo_enabled", "compiler": "go_version", "archive": "go_archive_sha256", "digest": "go_source_binary_sha256", "size": "go_source_binary_bytes"}.get(change)
    if key:
        manifest[key] = "wrong"
    elif change == "extra-source":
        manifest["source_files"]["../../unreviewed"] = "b" * 64
    else:
        manifest["source_files"].pop("go.mod")
    receipt.write_text(json.dumps(manifest))
    with pytest.raises((AssertionError, ValueError)):
        PROBE["bind_go_runtime"](binary, receipt)


def test_equal_bytes_replaced_helper_fails_final_identity_check(preparation):
    binary, receipt, _ = preparation
    _, _, unchanged = PROBE["bind_go_runtime"](binary, receipt)
    replacement = binary.with_suffix(".replacement")
    replacement.write_bytes(binary.read_bytes())
    replacement.chmod(0o700)
    replacement.replace(binary)
    with pytest.raises(AssertionError):
        unchanged()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "oversize"])
def test_nonregular_alias_and_oversized_preparation_evidence_refused(tmp_path, kind):
    target, actual = tmp_path / "target", tmp_path / "actual"
    actual.write_bytes(b"12345")
    if kind == "symlink":
        target.symlink_to(actual)
    elif kind == "hardlink":
        os.link(actual, target)
    elif kind == "fifo":
        os.mkfifo(target)
    else:
        target.write_bytes(b"123456789")
    with pytest.raises((OSError, ValueError)):
        PROBE["bounded_file"](target, 8)


def test_file_bound_accepts_exact_limit_and_refuses_one_byte_more(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"12345678")
    binding, raw = PROBE["bounded_file"](target, 8, retain=True)
    assert binding["bytes"] == 8 and raw == b"12345678"
    target.write_bytes(raw + b"9")
    with pytest.raises(ValueError):
        PROBE["bounded_file"](target, 8)
