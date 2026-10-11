"""Identity and archive admission for finite published-image qualification."""

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "ghcr.io/sourcebastion/sourcebastion-scanner"
S01_ARTIFACTS = {"amd64": 11468298212, "arm64": 11469000360}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise ValueError("published-digest-required")
    return value


def release_identity(release, tag, source, resolved_source, image_digest):
    if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag) is None:
        raise ValueError("exact-release-tag-required")
    if re.fullmatch(r"[0-9a-f]{40}", source) is None or source != resolved_source:
        raise ValueError("release-source-mismatch")
    if (release.get("tag_name") != tag or release.get("draft") is not False
            or not release.get("published_at") or release.get("prerelease") is not False):
        raise ValueError("published-stable-release-required")
    return {"release_tag": tag, "source_sha": source, "release_id": release["id"],
            "published_at": release["published_at"], "image": IMAGE + "@" + digest(image_digest)}


def native_descriptor(raw, index_digest, architecture):
    if architecture not in S01_ARTIFACTS or "sha256:" + sha(raw) != digest(index_digest):
        raise ValueError("published-index-identity-mismatch")
    if len(raw) > 2 * 1024**2:
        raise ValueError("published-index-bound")
    index = json.loads(raw)
    if index.get("schemaVersion") != 2:
        raise ValueError("published-index-schema-refused")
    rows = [row for row in index["manifests"]
            if row.get("platform", {}).get("os") == "linux"
            and row["platform"].get("architecture") == architecture]
    if len(rows) != 1:
        raise ValueError("unique-published-native-manifest-required")
    row = rows[0]
    digest(row["digest"])
    if type(row["size"]) is not int or not 0 < row["size"] <= 2 * 1024**2:
        raise ValueError("published-native-manifest-bound")
    return row


def bind_native(raw, descriptor, inspected, architecture):
    if len(raw) != descriptor["size"] or "sha256:" + sha(raw) != descriptor["digest"]:
        raise ValueError("published-native-manifest-mismatch")
    manifest = json.loads(raw)
    config = digest(manifest["config"]["digest"])
    if (inspected["Id"] != config or inspected["Architecture"] != architecture
            or inspected["Os"] != "linux"):
        raise ValueError("pulled-native-config-mismatch")
    return {"architecture": architecture, "native_manifest": descriptor["digest"],
            "config_digest": config, "layers": manifest["layers"]}


def extract_s01(archive, output, architecture):
    review = json.loads((ROOT / "evaluation/m046/evidence/direct-alpine-independent-verification.json").read_bytes())
    row = next(row for row in review["architectures"] if row["architecture"] == architecture)
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != row["oci_zip_sha256"]:
            raise ValueError("frozen-s01-zip-digest-mismatch")
    with zipfile.ZipFile(archive) as bundle:
        if sorted(bundle.namelist()) != ["runtime.oci.tar", "runtime.oci.tar.sha256"]:
            raise ValueError("frozen-s01-zip-entry-set-refused")
        info = bundle.getinfo("runtime.oci.tar")
        if info.file_size != row["image_cost"]["archive_bytes"] or info.flag_bits & 1:
            raise ValueError("frozen-s01-zip-size-refused")
        with bundle.open(info) as source, output.open("xb") as target:
            calculated = hashlib.sha256()
            while chunk := source.read(1024**2):
                calculated.update(chunk)
                target.write(chunk)
        if calculated.hexdigest() != row["oci_sha256"]:
            raise ValueError("frozen-s01-archive-digest-mismatch")


def advisory_files(root):
    """Hash a finite regular-file generation; never follow links or admit paths."""
    result, total = {}, 0
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        relative = path.relative_to(root).as_posix()
        # The reviewed consumer bounds the entire advisory generation to 4GiB.
        # Current upstream vulnerability.db is over 3GiB; a separate 2GiB
        # per-file ceiling incorrectly refuses an otherwise admitted generation.
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4 * 1024**3
                or len(result) >= 16 or any(part in {"", ".", ".."} for part in PurePosixPath(relative).parts)):
            raise ValueError("shared-advisory-file-refused")
        total += info.st_size
        if total > 4 * 1024**3:
            raise ValueError("shared-advisory-size-bound")
        with path.open("rb") as stream:
            result[relative] = {"sha256": hashlib.file_digest(stream, "sha256").hexdigest(), "bytes": info.st_size}
    if not {"snapshot.json", "6/vulnerability.db"} <= result.keys():
        raise ValueError("shared-advisory-generation-incomplete")
    return result


def verify_advisories(root, manifest, expected_sha256):
    raw = manifest.read_bytes()
    if sha(raw) != expected_sha256 or len(raw) > 65536:
        raise ValueError("shared-advisory-manifest-mismatch")
    if advisory_files(root) != json.loads(raw):
        raise ValueError("shared-advisory-content-mismatch")
    return sha((root / "snapshot.json").read_bytes())


def compare_native(left, right):
    """Compare retained native receipts, without promoting finite proof to acceptance."""
    from inventory_release import measured_resources

    receipts, cases = [], []
    arms = ("corpus", "flat-1000", "flat-10000", "flat-100000", "flat-100001", "graph", "expansion")
    for root, arch in ((left, "amd64"), (right, "arm64")):
        receipt = json.loads((root / "receipt.json").read_bytes())
        if receipt["status"] != "finite-published-native-passed" or receipt["architecture"] != arch or receipt["acceptance"] is not False:
            raise ValueError("both-finite-native-proofs-required")
        # Bind every archived observation to the driver's retained file map.
        actual = {path.relative_to(root).as_posix(): sha(path.read_bytes())
                  for path in root.rglob("*") if path.is_file() and path != root / "receipt.json"}
        if actual != receipt["retained_files"]:
            raise ValueError("native-retained-file-binding-mismatch")
        resources = [root / f"inventory-resources-{arm}-{repeat}/resources.json"
                     for arm in arms for repeat in range(1, 4)]
        resources += [root / f"entrypoint/repeat-{repeat}/entrypoint-resources/resources.json" for repeat in range(1, 4)]
        for path in resources:
            observed = measured_resources(json.loads(path.read_bytes()))
            workload = (path.parent / "workload.json").read_bytes()
            if (observed["architecture"] != arch or observed["image_id"] != receipt["config_digest"]
                    or observed["status"] != "passed" or not workload or sha(workload) != observed["workload_sha256"]):
                raise ValueError("native-resource-workload-binding-mismatch")
        proof = json.loads((root / "source-expectations.stdout").read_bytes())
        case_map = {case["case"]: case["inventory_sha256"] for case in proof["cases"]}
        if len(proof["cases"]) != 64 or len(case_map) != 64 or any(case["expectation_disagreement"] is not None for case in proof["cases"]):
            raise ValueError("complete-independent-corpus-proof-required")
        for repeat in range(1, 4):
            repeated = json.loads((root / f"inventory-resources-corpus-{repeat}/workload.json").read_bytes())
            repeated_cases = {case["case"]: case["inventory_sha256"] for case in repeated["cases"]}
            if (len(repeated["cases"]) != 64 or repeated_cases != case_map
                    or any(case["expectation_disagreement"] is not None for case in repeated["cases"])):
                raise ValueError("repeated-corpus-disagreement")
        size = json.loads((root / "frozen-s01-growth.json").read_bytes())
        if (size["status"] != "passed" or size["candidate_manifest"] != receipt["native_manifest"]
                or size["tested_image_id"] != receipt["config_digest"]
                or size["baseline_kind"] != "frozen-s01-pre-inventory-layer-prefix"):
            raise ValueError("frozen-s01-published-growth-required")
        receipts.append(receipt)
        cases.append(case_map)
    for key in ("image", "source_sha", "release_tag", "release_id", "shared_advisory_manifest_sha256", "advisory_snapshot_sha256"):
        if receipts[0][key] != receipts[1][key]:
            raise ValueError("cross-architecture-identity-mismatch:" + key)
    if cases[0] != cases[1]:
        raise ValueError("cross-architecture-canonical-corpus-mismatch")
    return {"schema_version": "m046.published-native-comparison/1", "status": "finite-published-native-verified",
            "acceptance": False, "source_sha": receipts[0]["source_sha"], "image": receipts[0]["image"],
            "advisory_snapshot_sha256": receipts[0]["advisory_snapshot_sha256"],
            "equal_canonical_cases": 64, "resource_workload_bindings": 48,
            "remaining_acceptance": receipts[0]["remaining_acceptance"]}
