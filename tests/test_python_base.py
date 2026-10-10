"""The release updater verifies registry bytes, platforms and interpreter versions."""

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("python_base", ROOT / "scripts/python_base.py")
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


@pytest.mark.parametrize("failure", [None, "digest", "size", "missing-arm", "duplicate-arm", "version", "architecture"])
def test_official_registry_resolution_verifies_both_native_configs(monkeypatch, failure):
    blobs, manifests = {}, []
    def descriptor(value):
        raw = json.dumps(value).encode()
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        blobs[digest] = raw
        return {"digest": digest, "size": len(raw)}
    for arch in ("amd64", "arm64"):
        config = descriptor({"os": "linux", "architecture": "s390x" if failure == "architecture" else arch,
                             "config": {"Env": ["PYTHON_VERSION=" + ("3.14.8" if failure == "version" else "3.14.9")]}})
        manifest = descriptor({"config": config})
        manifest["platform"] = {"os": "linux", "architecture": arch}
        manifests.append(manifest)
    if failure == "missing-arm":
        manifests.pop()
    if failure == "duplicate-arm":
        manifests.append(manifests[-1])
    if failure == "size":
        manifests[0]["size"] += 1
    if failure == "digest":
        blobs[manifests[0]["digest"]] = b"x" * manifests[0]["size"]
    index = json.dumps({"manifests": manifests}).encode()
    calls = []
    def fetch(url, *, token=None):
        calls.append(url)
        if "auth.docker.io" in url:
            assert token is None
            return b'{"token":"anonymous-pull"}'
        assert token == "anonymous-pull"
        return index if url.endswith("3.14.9-alpine3.23") else blobs[url.rsplit("/", 1)[1]]
    monkeypatch.setattr(base, "fetch", fetch)
    if failure:
        with pytest.raises(ValueError, match="python-base-"):
            base.resolve("3.14.9", "3.23")
    else:
        tag, digest, native = base.resolve("3.14.9", "3.23")
        assert tag == "3.14.9-alpine3.23"
        assert digest == "sha256:" + hashlib.sha256(index).hexdigest()
        assert native == {row["platform"]["architecture"]: row["digest"] for row in manifests}
        assert len(calls) == 6
