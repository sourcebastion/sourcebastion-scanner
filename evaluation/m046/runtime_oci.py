"""Bounded OCI-export identity and compressed added-layer audit, not provenance."""

import hashlib
import gzip
import argparse
import json
import math
import os
from pathlib import Path
import re
import resource
import stat
import tarfile
import time

ARCHIVE_LIMIT = 2 * 1024**3
JSON_LIMIT = 1024**2
METADATA_LIMIT = 16 * 1024**2
PROPOSED_ADDED_BYTES = 250 * 1024**2
EXPANDED_LIMIT = 4 * 1024**3
AUDIT_WALL_SECONDS = 120


def document(content):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate OCI JSON key")
            result[key] = value
        return result

    if len(content) > JSON_LIMIT:
        raise ValueError("OCI JSON exceeds bound")

    def reject(value):
        raise ValueError("nonfinite OCI JSON number: " + value)

    def finite(value):
        number = float(value)
        return number if math.isfinite(number) else reject(value)

    return json.loads(content, object_pairs_hook=unique, parse_constant=reject, parse_float=finite)


def audit(path, baseline, loaded):
    """Read trusted build output without extracting paths or unpacking layers."""
    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= ARCHIVE_LIMIT:
            raise ValueError("bounded regular OCI archive required")
        result = audit_stream(stream, baseline, loaded, before.st_size)
        key = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mode,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if key(before) != key(os.fstat(stream.fileno())) or key(before) != key(path.lstat()):
            raise ValueError("OCI archive identity changed")
        return result


def audit_stream(stream, baseline, loaded, archive_bytes):
    deadline = time.monotonic() + AUDIT_WALL_SECONDS
    if not 0 < archive_bytes <= ARCHIVE_LIMIT:
        raise ValueError("OCI archive exceeds separate 2 GiB artifact bound")
    blobs, small, members, total, metadata_bytes = {}, {}, set(), 0, 0
    with tarfile.open(fileobj=stream, mode="r:") as archive:
        for item in archive:
            if time.monotonic() > deadline:
                raise ValueError("OCI audit deadline exceeded")
            if len(members) >= 4096 or item.name in members:
                raise ValueError("duplicate or excessive OCI members")
            members.add(item.name)
            if item.isdir() and item.name in {"blobs", "blobs/sha256"}:
                continue
            if not item.isfile() or not re.fullmatch(r"(?:index.json|oci-layout|blobs/sha256/[0-9a-f]{64})", item.name):
                raise ValueError("unsafe OCI member")
            total += item.size
            if item.size < 0 or total > ARCHIVE_LIMIT:
                raise ValueError("OCI contents exceed bound")
            member = archive.extractfile(item)
            checksum, retained, count = hashlib.sha256(), bytearray(), 0
            while chunk := member.read(1024**2):
                if time.monotonic() > deadline:
                    raise ValueError("OCI audit deadline exceeded")
                checksum.update(chunk)
                count += len(chunk)
                if item.size <= JSON_LIMIT:
                    retained.extend(chunk)
            if count != item.size:
                raise ValueError("truncated OCI member")
            if item.name.startswith("blobs/"):
                digest = "sha256:" + checksum.hexdigest()
                if item.name != "blobs/sha256/" + checksum.hexdigest():
                    raise ValueError("OCI blob digest mismatch")
                blobs[digest] = {"size": count}
            if count <= JSON_LIMIT:
                metadata_bytes += count
                if metadata_bytes > METADATA_LIMIT:
                    raise ValueError("OCI retained metadata exceeds bound")
                small[item.name] = bytes(retained)
    if document(small["oci-layout"]) != {"imageLayoutVersion": "1.0.0"}:
        raise ValueError("unsupported OCI layout")
    index = document(small["index.json"])
    if (
        type(index.get("schemaVersion")) is not int
        or index["schemaVersion"] != 2
        or len(index.get("manifests", [])) != 1
    ):
        raise ValueError("one native image without attestations required")

    def referenced(descriptor, media):
        if descriptor.get("mediaType") not in media:
            raise ValueError("unexpected OCI media type")
        digest, size = descriptor.get("digest"), descriptor.get("size")
        if type(size) is not int or size < 0 or blobs.get(digest) != {"size": size}:
            raise ValueError("OCI descriptor size or digest mismatch")
        return digest

    manifest_digest = referenced(index["manifests"][0], {"application/vnd.oci.image.manifest.v1+json"})
    manifest = document(small["blobs/sha256/" + manifest_digest[7:]])
    if type(manifest.get("schemaVersion")) is not int or manifest["schemaVersion"] != 2:
        raise ValueError("unexpected image manifest schema")
    config_digest = referenced(manifest["config"], {"application/vnd.oci.image.config.v1+json"})
    config = document(small["blobs/sha256/" + config_digest[7:]])
    selected_platform = index["manifests"][0].get("platform")
    if selected_platform is not None and (
        selected_platform.get("os") != config.get("os")
        or selected_platform.get("architecture") != config.get("architecture")
        or selected_platform.get("variant", "") not in ({"", "v8"} if config.get("architecture") == "arm64" else {""})
    ):
        raise ValueError("OCI selected platform differs from native runtime")
    layers = manifest["layers"]
    if not isinstance(layers, list) or not 1 <= len(layers) <= 256:
        raise ValueError("bounded image layers required")
    for layer in layers:
        referenced(layer, {"application/vnd.oci.image.layer.v1.tar+gzip"})
    base_layers = baseline["manifest"]["layers"]
    layer_identity = lambda layer: (layer["mediaType"], layer["digest"], layer["size"])
    if len(layers) <= len(base_layers) or list(map(layer_identity, layers[: len(base_layers)])) != list(
        map(layer_identity, base_layers)
    ):
        raise ValueError("runtime does not preserve exact compressed baseline layer prefix")
    base = baseline["configuration"]
    diff_ids = config["rootfs"]["diff_ids"]
    if (
        config.get("os") != "linux"
        or config.get("architecture") != base["architecture"]
        or config["rootfs"].get("type") != "layers"
        or len(diff_ids) != len(layers)
        or diff_ids[: len(base_layers)] != base["rootfs"]["diff_ids"]
        or loaded.get("Id") != config_digest
        or loaded.get("Architecture") != config["architecture"]
        or loaded.get("Os") != "linux"
        or loaded.get("RootFS", {}).get("Layers") != diff_ids
    ):
        raise ValueError("loaded native runtime and exported OCI identities differ")
    for key in ("User", "Entrypoint", "Cmd", "WorkingDir"):
        if config["config"].get(key) != base["config"].get(key):
            raise ValueError("runtime overlay changes released image defaults")
    expanded, expanded_hashes = 0, []
    stream.seek(0)
    with tarfile.open(fileobj=stream, mode="r:") as archive:
        for layer, expected_diff in zip(layers, diff_ids):
            member = archive.extractfile("blobs/sha256/" + layer["digest"][7:])
            checksum = hashlib.sha256()
            with gzip.GzipFile(fileobj=member) as decoded:
                while chunk := decoded.read(1024**2):
                    expanded += len(chunk)
                    if expanded > EXPANDED_LIMIT or time.monotonic() > deadline:
                        raise ValueError("expanded OCI layers exceed audit budget")
                    checksum.update(chunk)
            actual_diff = "sha256:" + checksum.hexdigest()
            if actual_diff != expected_diff:
                raise ValueError("compressed OCI layer differs from tested runtime diff ID")
            expanded_hashes.append(actual_diff)
    added = layers[len(base_layers) :]
    added_bytes = sum(layer["size"] for layer in added)
    return {
        "status": "actual-compressed-layer-audit-only; signatures pending",
        "architecture": config["architecture"],
        "manifest_digest": manifest_digest,
        "configuration_digest": config_digest,
        "baseline_layers": len(base_layers),
        "added_layers": added,
        "added_compressed_bytes": added_bytes,
        "proposed_added_limit_bytes": PROPOSED_ADDED_BYTES,
        "fits_proposed_limit": added_bytes <= PROPOSED_ADDED_BYTES,
        "verified_blob_count": len(blobs),
        "archive_bytes": archive_bytes,
        "verified_expanded_bytes": expanded,
        "verified_diff_ids": expanded_hashes,
        "expanded_audit_limit_bytes": EXPANDED_LIMIT,
        "audit_wall_limit_seconds": AUDIT_WALL_SECONDS,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--pins", type=Path, required=True)
    parser.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--loaded", type=Path, required=True)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (1024**3,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
    pins = document(args.pins.read_bytes())
    loaded = document(args.loaded.read_bytes())
    print(json.dumps(audit(args.archive, pins["architectures"][args.architecture], loaded)))


if __name__ == "__main__":
    main()
