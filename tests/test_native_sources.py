"""Source publication refuses changed inputs; preparation never executes them."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("native_sources", ROOT / "scripts/native_sources.py")
sources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sources)


@pytest.fixture
def source(tmp_path):
    body = b"original source archive bytes"
    file = tmp_path / "example-1.tar.gz"
    file.write_bytes(body)
    digest = hashlib.sha256(body).hexdigest()
    value = {"repository": sources.REPOSITORY, "bundle_sha256": "a" * 64,
             "manifest_digest": "sha256:" + "b" * 64,
             "archives": [{"filename": file.name, "url": "https://example.invalid/source",
                           "sha256": digest, "bytes": len(body), "components": ["example-1"]}]}
    notices = {"components": [{"id": "example-1", "license": "LGPL-3.0-or-later",
                              "source_url": "https://example.invalid/source", "source_sha256": digest}]}
    pin = tmp_path / "pins.json"
    pin.write_text(json.dumps(value))
    return tmp_path, value, notices, pin


def test_committed_pins_cover_every_copyleft_notice():
    assert len(sources.pins()["archives"]) == 9


def test_deterministic_original_archives_and_checksum_file(source):
    directory, value, _, _ = source
    one, two = directory / "one.tar", directory / "two.tar"
    value["bundle_sha256"] = sources.build(value, directory, one)
    assert sources.build(value, directory, two) == value["bundle_sha256"]
    sources.verify_bundle(value, two)
    with tarfile.open(one) as archive:
        assert archive.getnames() == ["SHA256SUMS", "example-1.tar.gz"]
        assert archive.extractfile("example-1.tar.gz").read() == b"original source archive bytes"
        assert archive.extractfile("SHA256SUMS").read().decode().startswith(value["archives"][0]["sha256"])


@pytest.mark.parametrize("change", ["same-size", "missing", "symlink"])
def test_changed_sources_refuse_before_bundle_creation(source, change):
    directory, value, _, _ = source
    path = directory / "example-1.tar.gz"
    if change == "same-size":
        path.write_bytes(b"X" * path.stat().st_size)
    else:
        original = path.read_bytes()
        path.unlink()
        if change == "symlink":
            other = directory / "other"
            other.write_bytes(original)
            path.symlink_to(other)
    output = directory / "refused.tar"
    with pytest.raises(ValueError, match="disagree"):
        sources.build(value, directory, output)
    assert not output.exists()


@pytest.mark.parametrize("change", ["repository", "url", "traversal", "duplicate", "digest", "size", "coverage"])
def test_malformed_or_uncovered_pins_refuse(source, change):
    _, value, notices, path = source
    item = value["archives"][0]
    if change == "repository":
        value["repository"] = "ghcr.io/another/repository"
    elif change == "url":
        item["url"] = "http://example.invalid/source"
    elif change == "traversal":
        item["filename"] = "../example.tar.gz"
    elif change == "duplicate":
        value["archives"].append(copy.deepcopy(item))
    elif change == "digest":
        item["sha256"] = "not-a-digest"
    elif change == "size":
        item["bytes"] = True
    else:
        item["components"] = ["unrelated"]
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        sources.pins(path, notices)


def test_failed_download_leaves_no_publishable_cache(source, monkeypatch):
    directory, value, _, _ = source
    def wrong_download(command, **kwargs):
        Path(command[command.index("--output") + 1]).write_bytes(b"wrong")
    monkeypatch.setattr(sources.subprocess, "run", wrong_download)
    cache = directory / "downloads"
    with pytest.raises(ValueError, match="disagrees"):
        sources.download(value, cache)
    assert list(cache.iterdir()) == []


def test_bundle_retrieval_refuses_changed_bytes(source):
    directory, value, _, _ = source
    bundle = directory / "bundle.tar"
    value["bundle_sha256"] = sources.build(value, directory, bundle)
    with bundle.open("r+b") as stream:
        stream.write(b"X")
    with pytest.raises(ValueError, match="bundle disagrees"):
        sources.verify_bundle(value, bundle)
