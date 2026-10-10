"""Frozen numeric release gates. Receipts are evidence inputs, not attestations."""

import hashlib
import gzip
import json
import math
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]
FROZEN = {
    "cpu_quota": 2, "memory_bytes": 2147483648, "swap_bytes": 0,
    "cpu_usec": 120000000, "wall_seconds": 150, "pids": 256,
    "added_compressed_layer_bytes": 262144000, "repeats_per_native_architecture": 3,
}


def policy():
    value = json.loads((ROOT / "evaluation/m046/release-budgets-v1.json").read_text())
    if value.get("schema_version") != "m046.release-budgets/1" or any(value.get(k) != v for k, v in FROZEN.items()):
        raise ValueError("unreviewed-frozen-budget-change")
    return value


def measured_resources(observed):
    policy()
    if observed.get("observer") != "host-cgroup-v2" or observed.get("architecture") not in {"amd64", "arm64"}:
        raise ValueError("host-native-resource-observation-required")
    for field in ("cpu_usec", "memory_peak", "swap_peak", "pids_peak", "wall_seconds"):
        number = observed[field]
        if type(number) not in (int, float) or not math.isfinite(number) or number < 0:
            raise ValueError("invalid-resource-measurement")
    ceilings = {"cpu_usec": FROZEN["cpu_usec"], "memory_peak": FROZEN["memory_bytes"],
                "swap_peak": 0, "pids_peak": FROZEN["pids"], "wall_seconds": FROZEN["wall_seconds"]}
    if any(observed[k] > limit for k, limit in ceilings.items()):
        raise ValueError("dependency-resource-ceiling-exceeded")
    if observed.get("oom_kill") != 0 or observed.get("exit_code") != 0 or observed.get("removed") is not True:
        raise ValueError("dependency-resource-lifecycle-failed")
    return observed


def oci_layers(path, architecture):
    """Verify referenced OCI bytes without extracting an untrusted archive.

    Only one Linux native image is admitted. Added-layer size is calculated
    from verified compressed descriptors, never Docker's uncompressed Size.
    """
    if architecture not in {"amd64", "arm64"}:
        raise ValueError("native-architecture-required")
    with tarfile.open(path, "r:*") as archive:
        members, names = {}, set()
        for member in archive:
            if len(names) >= 8192 or member.name in names:
                raise ValueError("oci-entry-set-invalid")
            names.add(member.name)
            if not (member.isfile() or member.isdir()) or member.sparse is not None:
                raise ValueError("oci-special-entry-refused")
            if member.isfile():
                if member.size > 2 * 1024**3 or member.name.startswith("/") or ".." in member.name.split("/"):
                    raise ValueError("oci-entry-invalid")
                members[member.name] = member
        def read(name, maximum):
            member = members[name]
            if not 0 < member.size <= maximum:
                raise ValueError("oci-metadata-size-invalid")
            with archive.extractfile(member) as stream:
                return stream.read(maximum + 1)
        def blob(descriptor, *, metadata=False):
            digest = descriptor["digest"]
            if not isinstance(digest, str) or len(digest) != 71 or not digest.startswith("sha256:") or any(
                c not in "0123456789abcdef" for c in digest[7:]
            ):
                raise ValueError("oci-digest-invalid")
            member = members["blobs/sha256/" + digest[7:]]
            if type(descriptor["size"]) is not int or descriptor["size"] != member.size:
                raise ValueError("oci-descriptor-size-mismatch")
            calculated = hashlib.sha256()
            with archive.extractfile(member) as stream:
                while chunk := stream.read(1024**2):
                    calculated.update(chunk)
            if calculated.hexdigest() != digest[7:]:
                raise ValueError("oci-blob-digest-mismatch")
            return json.loads(read(member.name, 2 * 1024**2)) if metadata else None
        index = json.loads(read("index.json", 2 * 1024**2))
        manifests = index["manifests"]
        if len(manifests) != 1:
            raise ValueError("oci-one-native-manifest-required")
        descriptor = manifests[0]
        manifest = blob(descriptor, metadata=True)
        # Buildx may put a single image index under the root index.
        if "manifests" in manifest:
            if len(manifest["manifests"]) != 1:
                raise ValueError("oci-one-native-manifest-required")
            descriptor = manifest["manifests"][0]
            manifest = blob(descriptor, metadata=True)
        config = blob(manifest["config"], metadata=True)
        if config.get("os") != "linux" or config.get("architecture") != architecture:
            raise ValueError("oci-native-architecture-mismatch")
        layers = manifest["layers"]
        if not layers or len(layers) > 256:
            raise ValueError("oci-layer-count-invalid")
        rootfs = config.get("rootfs", {})
        diff_ids = rootfs.get("diff_ids", [])
        if rootfs.get("type") != "layers" or len(diff_ids) != len(layers):
            raise ValueError("oci-rootfs-layer-closure-mismatch")
        expanded_bytes = 0
        for layer, expected in zip(layers, diff_ids):
            if layer["mediaType"] not in {"application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.docker.image.rootfs.diff.tar.gzip"}:
                raise ValueError("oci-compressed-layer-required")
            blob(layer)
            # A manifest could otherwise reference tiny arbitrary blobs under
            # the same tested config. Bind compressed bytes to its actual
            # rootfs diff IDs by streaming decompression, without extraction.
            calculated = hashlib.sha256()
            member = members["blobs/sha256/" + layer["digest"][7:]]
            with archive.extractfile(member) as stream, gzip.GzipFile(fileobj=stream) as decoded:
                while chunk := decoded.read(1024**2):
                    expanded_bytes += len(chunk)
                    if expanded_bytes > 8 * 1024**3:
                        raise ValueError("oci-expanded-image-bound")
                    calculated.update(chunk)
            if "sha256:" + calculated.hexdigest() != expected:
                raise ValueError("oci-rootfs-diff-id-mismatch")
        return {"manifest_digest": descriptor["digest"], "config_digest": manifest["config"]["digest"], "architecture": architecture,
                "layers": [{"digest": layer["digest"], "size": layer["size"]} for layer in layers]}


def growth(before, after):
    policy()
    if before["architecture"] != after["architecture"]:
        raise ValueError("oci-baseline-architecture-mismatch")
    # Count every new compressed blob. Shared blobs may legitimately move;
    # a changed base is still charged, never credited as removed inventory.
    existing = {row["digest"] for row in before["layers"]}
    added = sum(row["size"] for row in after["layers"] if row["digest"] not in existing)
    if added > FROZEN["added_compressed_layer_bytes"]:
        raise ValueError("compressed-inventory-growth-ceiling-exceeded")
    return {"baseline_manifest": before["manifest_digest"], "candidate_manifest": after["manifest_digest"],
            "architecture": after["architecture"], "added_compressed_bytes": added,
            "ceiling": FROZEN["added_compressed_layer_bytes"]}
