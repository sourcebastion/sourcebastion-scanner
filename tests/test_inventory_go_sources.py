"""Go observation admission cannot manufacture selected version authority."""

import hashlib
import json
import time
import subprocess
from types import SimpleNamespace
from pathlib import Path
import pytest
from sourcebastion.inventory import go_sources
from sourcebastion.inventory.inputs import InputRefusal

CONTENT = b"module example.invalid/root\nrequire example.invalid/alpha v1.2.3 // indirect\n"


def document():
    return {
        "schema_version": "sourcebastion.go-source-observation/1",
        "parser": "golang.org/x/mod/modfile@v0.41.0",
        "source_sha256": hashlib.sha256(CONTENT).hexdigest(),
        "module": "example.invalid/root",
        "requirements": [
            {
                "ordinal": 0,
                "name": "example.invalid/alpha",
                "minimum_version": "v1.2.3",
                "indirect": True,
                "line": 2,
                "start_byte": 28,
                "end_byte": 65,
            }
        ],
        "unassessed_directives": [],
        "selected_versions": "unreported",
        "graph": "unreported",
    }


def decode(value):
    return go_sources.decode(json.dumps(value).encode(), CONTENT, check=lambda: None)


def test_normalized_minimum_and_indirect_are_source_assertions():
    result = decode(document())
    assert result.requirements[0].minimum_version == "v1.2.3" and result.requirements[0].indirect
    assert result.selected_versions == result.graph == "unreported"


@pytest.mark.parametrize(
    "key,value",
    [
        ("source_sha256", "0" * 64),
        ("selected_versions", "complete"),
        ("graph", "complete"),
        ("unassessed_directives", ["unassessed-secret-directive"]),
        ("unexpected", "secret"),
    ],
)
def test_unbound_or_authoritative_response_refused(key, value):
    raw = document()
    raw[key] = value
    with pytest.raises(InputRefusal, match="invalid-go-source-observation"):
        decode(raw)


@pytest.mark.parametrize(
    "key,value",
    [
        ("ordinal", 1),
        ("ordinal", True),
        ("line", 1),
        ("start_byte", 1000),
        ("end_byte", 1),
        ("minimum_version", "master"),
    ],
)
def test_wrong_locator_or_identity_refused(key, value):
    raw = document()
    raw["requirements"][0][key] = value
    with pytest.raises(InputRefusal):
        decode(raw)


def test_duplicate_names_require_explicit_uncertainty():
    raw = document()
    row = dict(raw["requirements"][0], ordinal=1, start_byte=66, end_byte=70)
    raw["requirements"].append(row)
    with pytest.raises(InputRefusal):
        decode(raw)


def test_missing_runtime_is_typed_unsupported_without_execution():
    result = go_sources.parse(CONTENT, runtime=None, deadline=time.monotonic() + 5, check=lambda: None)
    assert result.disposition == "unsupported" and result.observation is None


def test_runtime_requires_absolute_controller_artifact_and_digest():
    with pytest.raises(ValueError):
        go_sources.Runtime(Path("customer/parser"), "0" * 64)
    with pytest.raises(ValueError):
        go_sources.Runtime(Path("/trusted/parser"), "secret")


def test_wrong_digest_and_symlink_refuse_without_executing(tmp_path):
    binary = tmp_path / "helper"
    binary.write_bytes(b"#!/bin/sh\necho secret\n")
    binary.chmod(0o700)
    result = go_sources.parse(
        CONTENT, runtime=go_sources.Runtime(binary, "0" * 64), deadline=time.monotonic() + 5, check=lambda: None
    )
    assert result.disposition == "failed" and result.observation is None and "secret" not in repr(result)
    alias = tmp_path / "alias"
    alias.symlink_to(binary)
    result = go_sources.parse(
        CONTENT,
        runtime=go_sources.Runtime(alias, hashlib.sha256(binary.read_bytes()).hexdigest()),
        deadline=time.monotonic() + 5,
        check=lambda: None,
    )
    assert result.observation is None


def test_shared_controller_refusal_propagates():
    def stop():
        raise InputRefusal("composition-check-budget-exceeded")

    with pytest.raises(InputRefusal, match="composition-check-budget-exceeded"):
        go_sources.parse(
            CONTENT,
            runtime=go_sources.Runtime(Path("/trusted/parser"), "0" * 64),
            deadline=time.monotonic() + 5,
            check=stop,
        )


@pytest.mark.parametrize("failure", ["exec", "timeout", "decode"])
def test_every_post_open_failure_revalidates_runtime_custody(tmp_path, monkeypatch, failure):
    binary = tmp_path / "helper"
    binary.write_bytes(b"\x7fELFsynthetic-controller-artifact")
    runtime = go_sources.Runtime(binary, hashlib.sha256(binary.read_bytes()).hexdigest())

    def failed_execution(*args, **kwargs):
        if failure == "decode":
            return SimpleNamespace(returncode=0, stdout=b"{}", stderr=b"")
        binary.unlink()
        if failure == "timeout":
            raise subprocess.TimeoutExpired("fixed-parser", 1)
        raise OSError("synthetic execution failure")

    def failed_decode(*args, **kwargs):
        binary.unlink()
        raise InputRefusal("invalid-go-source-observation")

    monkeypatch.setattr(go_sources.subprocess, "run", failed_execution)
    if failure == "decode":
        monkeypatch.setattr(go_sources, "decode", failed_decode)
    with pytest.raises(InputRefusal, match="changed-go-parser-runtime"):
        go_sources.parse(CONTENT, runtime=runtime, deadline=time.monotonic() + 5, check=lambda: None)
