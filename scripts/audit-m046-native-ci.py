"""Audit downloaded native CI receipts; this never grants S07 acceptance.

Input directory: GitHub API run.json and artifacts.json plus the eight zip
archives named below. Archive digests are verified before reading receipts.
No archive is extracted and no code from an archive is executed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import zipfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def audit(root):
    run = json.loads((root / "run.json").read_text())
    require(run["status"] == "completed" and run["conclusion"] == "success", "run-not-successful")
    metadata = json.loads((root / "artifacts.json").read_text())["artifacts"]
    names = [item["name"] for item in metadata]
    require(len(names) == len(set(names)), "duplicate-artifact-name")
    metadata = {item["name"]: item for item in metadata}
    result = {
        "schema_version": "m046.s07-prerequisite-audit/1",
        "status": "finite-ci-evidence-verified",
        "acceptance": False,
        "source_sha": run["head_sha"],
        "run_id": run["id"],
        "run_url": run["html_url"],
        "scope": "PR-built images; not published-digest, development, rollback or S07 acceptance.",
        "archives": {},
        "architectures": {},
    }
    case_maps = {}
    for arch in ("amd64", "arm64"):
        section = {"resources": [], "entrypoint_proofs": []}
        for kind in ("maintenance", "entrypoint", "real-grype", "source-expectations"):
            name = f"inventory-{kind}-{arch}"
            item = metadata[name]
            require(item["workflow_run"]["id"] == run["id"], "artifact-run-mismatch")
            require(item["workflow_run"]["head_sha"] == run["head_sha"], "artifact-source-mismatch")
            path = root / (name + ".zip")
            require(path.stat().st_size == item["size_in_bytes"], "archive-size-mismatch")
            require("sha256:" + digest(path.read_bytes()) == item["digest"], "archive-digest-mismatch")
            result["archives"][name] = {key: item[key] for key in ("id", "digest", "size_in_bytes")}
            with zipfile.ZipFile(path) as archive:
                members = archive.namelist()
                require(len(members) == len(set(members)), "duplicate-archive-member")
                require(sum(info.file_size for info in archive.infolist()) <= 16 * 1024 * 1024, "archive-too-large")

                def read(name):
                    return json.loads(archive.read(name))

                resources = [name for name in members if name.endswith("/resources.json")]
                if kind in ("maintenance", "entrypoint"):
                    expected_resources = (
                        {f"inventory-resources-{arm}-{repeat}/resources.json"
                         for arm in ("corpus", "flat-1000", "flat-10000", "flat-100000", "flat-100001", "graph", "expansion")
                         for repeat in range(1, 4)} if kind == "maintenance" else
                        {f"repeat-{repeat}/entrypoint-resources/resources.json" for repeat in range(1, 4)}
                    )
                    require(set(resources) == expected_resources, "resource-matrix-incomplete")
                    for member in resources:
                        receipt = read(member)
                        require(receipt["architecture"] == arch, "resource-architecture-mismatch")
                        require(receipt["status"] == "passed" and receipt["exit_code"] == 0 and receipt["removed"] is True, "resource-or-cleanup-failed")
                        require(0 <= receipt["cpu_usec"] <= 120_000_000 and 0 <= receipt["memory_peak"] <= 2_147_483_648
                                and receipt["swap_peak"] == 0 and 0 < receipt["pids_peak"] <= 256
                                and 0 <= receipt["wall_seconds"] <= 150 and receipt["oom_kill"] == 0, "resource-budget-exceeded")
                        workload = archive.read(member.rsplit("/", 1)[0] + "/workload.json")
                        require(bool(workload) and digest(workload) == receipt["workload_sha256"], "workload-binding-mismatch")
                        section["resources"].append({"archive": name, "path": member,
                                                     "receipt_sha256": digest(archive.read(member)), **receipt})
                if kind == "maintenance":
                    section["compressed_growth"] = read("inventory-compressed-growth.json")
                    for member in ("inventory-upgrade-diff.json", "inventory-current-oracle-diff.json"):
                        diff = read(member)
                        require(diff["status"] == "passed" and diff["corpus"]["cases_compared"] == 64
                                and not diff["corpus"]["changes"] and not diff["corpus"]["missing_cases"], "corpus-upgrade-refused")
                        section[member] = diff
                if kind == "entrypoint":
                    for repeat in range(1, 4):
                        prefix = f"repeat-{repeat}/"
                        proof = read(prefix + "proof.json")
                        require(proof["status"] == "native-installed-entrypoint-finite-passed"
                                and proof["all_required_advisory_groups"] is True, "entrypoint-proof-refused")
                        for key, member in (("host_observation_sha256", "host-observation.json"),
                                            ("control_sha256", "control/job.json"),
                                            ("receipt_sha256", "entrypoint-resources/workload.json")):
                            require(proof[key] == digest(archive.read(prefix + member)), "entrypoint-binding-mismatch")
                        section["entrypoint_proofs"].append({"repeat": repeat,
                            "proof_sha256": digest(archive.read(prefix + "proof.json")),
                            "matches": proof["matches"],
                            "provenance": {key: value for key, value in proof["provenance"].items() if key != "bindings"},
                            "bindings_sha256": digest(json.dumps(proof["provenance"]["bindings"], sort_keys=True, separators=(",", ":")).encode()),
                            "entrypoint_sha256": proof["provenance"]["bindings"]["entrypoint_sha256"],
                            "package_version": proof["provenance"]["bindings"]["package_version"]})
                if kind == "real-grype":
                    receipt = read("receipt.json")
                    require(receipt["status"] == "native-real-grype-finite-passed"
                            and receipt["known_advisory_on_each_selected_id"] is True, "real-grype-proof-refused")
                    section["matching"] = {key: receipt[key] for key in (
                        "consumer", "fixture_sha256", "binary_pins_sha256", "discovery_config_sha256",
                        "matches", "inventory_sha256", "sbom_sha256")}
                    binding = read("advisory-binding.json")
                    section["matching"]["advisory_files"] = {name: {key: info[key] for key in ("sha256", "bytes")}
                        for name, info in binding["binding"]["files"].items()}
                    section["matching"]["advisory_status"] = binding["status"]
                if kind == "source-expectations":
                    proof = read("inventory-source-expectations-native.json")
                    require(proof["architecture"] == {"amd64": "x86_64", "arm64": "aarch64"}[arch] and len(proof["cases"]) == 64
                            and all(case["expectation_disagreement"] is None for case in proof["cases"]), "source-oracle-disagreement")
                    case_maps[arch] = {case["case"]: case["inventory_sha256"] for case in proof["cases"]}
                    require(len(case_maps[arch]) == 64, "duplicate-corpus-case")
                    section["corpus"] = {"cases": 64, "case_inventory_sha256": case_maps[arch],
                        "expectations_sha256": proof["expectations_sha256"],
                        "historical_oracle_sha256": proof["historical_oracle_sha256"], "go_runtime": proof["go_runtime"]}
        section["maxima"] = {key: max(receipt[key] for receipt in section["resources"])
            for key in ("cpu_usec", "memory_peak", "pids_peak", "wall_seconds")}
        section["resource_receipts_verified"] = len(section["resources"])
        require(len({receipt["image_id"] for receipt in section["resources"]}) == 1, "resource-image-mismatch")
        require(section["compressed_growth"]["tested_image_id"] == section["resources"][0]["image_id"], "growth-image-mismatch")
        result["architectures"][arch] = section
    require(case_maps["amd64"] == case_maps["arm64"], "cross-architecture-inventory-disagreement")
    result["cross_architecture_canonical_inventory_digests_equal"] = True
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.artifacts_directory)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print("Verified 8 archive digests, 48 resource/workload bindings, 6 entrypoint bindings, and 64 equal native corpus digests. S07 acceptance remains open.")


if __name__ == "__main__":
    main()
