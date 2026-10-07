"""Actual archive tamper and baseline/runtime binding boundaries."""

from copy import deepcopy
import hashlib
import gzip
import io
import json
import tarfile

import pytest

from evaluation.m046.runtime_oci import audit
from evaluation.m046 import runtime_oci


def fixture():
    def layer_tar(name):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as archive:
            item = tarfile.TarInfo(name)
            item.size = 1
            archive.addfile(item, io.BytesIO(b"x"))
        return data.getvalue()

    base_content, new_content = layer_tar("base"), layer_tar("added")
    base_layer, new_layer = gzip.compress(base_content), gzip.compress(new_content)
    layer = lambda value: {
        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
        "digest": "sha256:" + hashlib.sha256(value).hexdigest(),
        "size": len(value),
    }
    config = {
        "os": "linux",
        "architecture": "amd64",
        "rootfs": {
            "type": "layers",
            "diff_ids": ["sha256:" + hashlib.sha256(content).hexdigest() for content in (base_content, new_content)],
        },
        "config": {"User": "sourcebastion", "Entrypoint": ["scanner"], "Cmd": None, "WorkingDir": "/app"},
    }
    base_config = deepcopy(config)
    base_config["rootfs"]["diff_ids"].pop()
    blobs = {}

    def blob(content, media):
        checksum = hashlib.sha256(content).hexdigest()
        blobs["blobs/sha256/" + checksum] = content
        return {"mediaType": media, "digest": "sha256:" + checksum, "size": len(content)}

    config_descriptor = blob(json.dumps(config).encode(), "application/vnd.oci.image.config.v1+json")
    blobs["blobs/sha256/" + layer(base_layer)["digest"][7:]] = base_layer
    blobs["blobs/sha256/" + layer(new_layer)["digest"][7:]] = new_layer
    manifest = {"schemaVersion": 2, "config": config_descriptor, "layers": [layer(base_layer), layer(new_layer)]}
    manifest_descriptor = blob(json.dumps(manifest).encode(), "application/vnd.oci.image.manifest.v1+json")
    blobs["index.json"] = json.dumps({"schemaVersion": 2, "manifests": [manifest_descriptor]}).encode()
    blobs["oci-layout"] = b'{"imageLayoutVersion":"1.0.0"}'
    baseline = {"manifest": {"layers": [layer(base_layer)]}, "configuration": base_config}
    loaded = {
        "Id": config_descriptor["digest"],
        "Architecture": "amd64",
        "Os": "linux",
        "RootFS": {"Layers": config["rootfs"]["diff_ids"]},
    }
    return blobs, baseline, loaded


def archive(path, blobs, extra=None):
    with tarfile.open(path, "w") as output:
        for name, content in blobs.items():
            item = tarfile.TarInfo(name)
            item.size = len(content)
            output.addfile(item, io.BytesIO(content))
        if extra:
            output.addfile(extra)


def test_added_cost_comes_from_verified_export_layers_and_loaded_image(tmp_path):
    blobs, base, loaded = fixture()
    path = tmp_path / "runtime.tar"
    archive(path, blobs)
    report = audit(path, base, loaded)
    assert report["added_compressed_bytes"] == report["added_layers"][0]["size"]
    assert report["verified_expanded_bytes"] == 20480
    assert report["verified_blob_count"] == 4
    assert report["configuration_digest"] == loaded["Id"]


@pytest.mark.parametrize(
    "change", ["blob", "baseline", "image", "rootfs", "architecture", "defaults", "descriptor", "duplicate-json"]
)
def test_changed_export_baseline_or_loaded_runtime_is_refused(tmp_path, change):
    blobs, base, loaded = fixture()
    if change == "blob":
        name = next(name for name in blobs if name.startswith("blobs/"))
        blobs[name] += b"tampered"
    elif change == "baseline":
        base["manifest"]["layers"][0]["size"] += 1
    elif change == "image":
        loaded["Id"] = "sha256:" + "0" * 64
    elif change == "rootfs":
        loaded["RootFS"]["Layers"] = ["sha256:" + "0" * 64]
    elif change == "architecture":
        loaded["Architecture"] = "arm64"
    elif change == "defaults":
        base["configuration"]["config"]["User"] = "root"
    elif change == "descriptor":
        index = json.loads(blobs["index.json"])
        index["manifests"][0]["size"] += 1
        blobs["index.json"] = json.dumps(index).encode()
    else:
        blobs["oci-layout"] = b'{"imageLayoutVersion":"1.0.0","imageLayoutVersion":"1.0.0"}'
    path = tmp_path / "runtime.tar"
    archive(path, blobs)
    with pytest.raises(ValueError):
        audit(path, base, loaded)


@pytest.mark.parametrize(
    "name,kind",
    [("../escape", tarfile.REGTYPE), ("blobs/sha256/" + "0" * 64, tarfile.SYMTYPE), ("index.json", tarfile.REGTYPE)],
)
def test_unsafe_or_duplicate_members_are_refused_without_extraction(tmp_path, name, kind):
    blobs, base, loaded = fixture()
    item = tarfile.TarInfo(name)
    item.type = kind
    item.linkname = "/etc/passwd" if kind == tarfile.SYMTYPE else ""
    path = tmp_path / "runtime.tar"
    archive(path, blobs, item)
    with pytest.raises(ValueError):
        audit(path, base, loaded)


def test_changed_layer_with_consistent_compressed_descriptors_still_cannot_forge_tested_filesystem(tmp_path):
    blobs, base, loaded = fixture()
    index = json.loads(blobs["index.json"])
    manifest = json.loads(blobs["blobs/sha256/" + index["manifests"][0]["digest"][7:]])
    changed = gzip.compress(b"different uncompressed filesystem")
    checksum = hashlib.sha256(changed).hexdigest()
    blobs["blobs/sha256/" + checksum] = changed
    manifest["layers"][1].update(digest="sha256:" + checksum, size=len(changed))
    content = json.dumps(manifest).encode()
    checksum = hashlib.sha256(content).hexdigest()
    blobs["blobs/sha256/" + checksum] = content
    index["manifests"][0].update(digest="sha256:" + checksum, size=len(content))
    blobs["index.json"] = json.dumps(index).encode()
    path = tmp_path / "runtime.tar"
    archive(path, blobs)
    with pytest.raises(ValueError, match="differs from tested runtime diff ID"):
        audit(path, base, loaded)


def test_expanded_gzip_and_archive_path_bounds_are_enforced(tmp_path, monkeypatch):
    blobs, base, loaded = fixture()
    path = tmp_path / "runtime.tar"
    archive(path, blobs)
    monkeypatch.setattr(runtime_oci, "EXPANDED_LIMIT", 1024)
    with pytest.raises(ValueError, match="expanded OCI layers exceed"):
        audit(path, base, loaded)
    link = tmp_path / "symlink"
    link.symlink_to(path)
    with pytest.raises(OSError):
        audit(link, base, loaded)


@pytest.mark.parametrize("content", [b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}', b'{"x":1e999}'])
def test_nonfinite_json_is_refused(content):
    with pytest.raises(ValueError, match="nonfinite"):
        runtime_oci.document(content)


def test_retained_metadata_and_exact_schema_type_are_bounded(tmp_path, monkeypatch):
    blobs, base, loaded = fixture()
    index = json.loads(blobs["index.json"])
    index["schemaVersion"] = 2.0
    blobs["index.json"] = json.dumps(index).encode()
    path = tmp_path / "runtime.tar"
    archive(path, blobs)
    with pytest.raises(ValueError, match="one native image"):
        audit(path, base, loaded)
    monkeypatch.setattr(runtime_oci, "METADATA_LIMIT", 4)
    with pytest.raises(ValueError, match="retained metadata"):
        audit(path, base, loaded)
