"""Isolated post-measurement pin/root audit, not a general SBOM oracle."""

import argparse
import hashlib
import json
from pathlib import Path
import resource
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from evaluation.m046.syft_control_audit import decode, hash_records

INVENTORY_VERSION = "m046-static-inventory-prototype-v5"
INVENTORY_REFUSALS = {"inventory-output-budget-exceeded", "semantic-expansion-budget-exceeded"}
EXPORT_REFUSALS = {"sbom-input-complexity-exceeded", "sbom-input-text-exceeded", "inventory-output-budget-exceeded"}


def audit(document, oracle, mode):
    if mode not in {"direct-inventory", "direct-cyclonedx"}:
        raise ValueError("unknown direct arm")
    if oracle["spec"]["kind"] != "pins":
        raise ValueError("only independent synthetic pin oracle admitted")
    if document.get("inventory_status") == "failed":
        codes = document.get("refusal_codes")
        if (
            set(document)
            != {
                "schema_version",
                "inventory_status",
                "sbom_status",
                "matching_status",
                "packages",
                "edges",
                "application_identities",
                "coverage",
                "refusal_codes",
                "refusal_stage",
                "source_inventory_status",
            }
            or document["schema_version"] != INVENTORY_VERSION
            or document["sbom_status"] != "not-run"
            or document["matching_status"] != "not-run"
            or any(document[name] != [] for name in ("packages", "edges", "application_identities"))
            or document["coverage"] != "prototype-static-python"
            or not isinstance(codes, list)
            or len(codes) != 1
            or codes[0] not in INVENTORY_REFUSALS
            or oracle["spec"]["count"] <= 10000
        ):
            raise ValueError("malformed refusal")
        if (
            codes[0] == "inventory-output-budget-exceeded"
            and (
                document["refusal_stage"] != "inventory-serialization"
                or document["source_inventory_status"] != "complete"
            )
        ) or (
            codes[0] == "semantic-expansion-budget-exceeded"
            and (
                document["refusal_stage"] != "inventory-evaluation"
                or document["source_inventory_status"] != "failed"
                or oracle["spec"]["count"] <= 100000
            )
        ):
            raise ValueError("unexpected refusal stage")
        return {
            "status": "controlled-refusal",
            "stage": document["refusal_stage"],
            "reason": codes[0],
            "source_inventory_status": document["source_inventory_status"],
        }
    if document.get("status") == "evaluation-export-refused":
        if (
            set(document)
            != {"status", "inventory_status", "sbom_status", "matching_status", "reason", "inventory_retention"}
            or mode != "direct-cyclonedx"
            or document.get("inventory_status") != "complete"
            or document.get("sbom_status") != "failed"
            or document.get("matching_status") != "not-run"
            or document.get("reason") not in EXPORT_REFUSALS
            or document.get("inventory_retention") != "not-assessed; this job retains one measured output only"
            or oracle["spec"]["count"] <= 10000
        ):
            raise ValueError("malformed export refusal")
        return {"status": "controlled-refusal", "stage": "export", "reason": document["reason"]}
    if mode == "direct-inventory":
        if document["inventory_status"] != "complete":
            raise ValueError("synthetic pins must have complete inventory")
        records = document["semantic_dimensions"]["occurrences"]
        inputs = {row["path"]: row["sha256"] for row in document["semantic_dimensions"]["inputs"]}
        if document["semantic_dimensions"]["relationships"] or document["edges"]:
            raise ValueError("flat requirements cannot invent dependency edges")
        retained = document
    else:
        if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.6":
            raise ValueError("unexpected direct SBOM format")
        if document.get("dependencies") or document.get("compositions") != [{"aggregate": "unknown"}]:
            raise ValueError("flat requirements graph is unknown")
        metadata_pairs = document["metadata"]["properties"]
        metadata = {row["name"]: row["value"] for row in metadata_pairs}
        if len(metadata) != len(metadata_pairs):
            raise ValueError("duplicate metadata property")
        retained = decode(metadata["sourcebastion:m046:inventory"])
        records, inputs, identifiers = [], {}, set()
        for component in document["components"]:
            ref = component["bom-ref"]
            if ref in identifiers:
                raise ValueError("duplicate occurrence ID")
            identifiers.add(ref)
            pairs = component["properties"]
            props = {row["name"]: row["value"] for row in pairs}
            if len(props) != len(pairs):
                raise ValueError("duplicate occurrence property")
            record = decode(props["sourcebastion:m046:occurrence"])
            expected_ref = (
                "m046-"
                + hashlib.sha256(
                    b"m046-syft-occurrence-v1\0m046-static-inventory-prototype-v5\0"
                    + json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
                ).hexdigest()
            )
            if ref != expected_ref:
                raise ValueError("occurrence ID not bound")
            checksum = decode(props["sourcebastion:m046:source_sha256"])
            name, version = record["package"][5:].split("@", 1)
            if (
                component["type"] != "library"
                or component["name"] != name
                or component["version"] != version
                or component["purl"] != f"pkg:pypi/{name}@{version}"
            ):
                raise ValueError("selected component identity mismatch")
            evidence = component["evidence"]["occurrences"]
            expected_evidence = {
                "bom-ref": ref + "-evidence",
                "location": record["path"],
                "additionalContext": record["locator"],
                "line": int(record["locator"].removeprefix("line:")),
            }
            if evidence != [expected_evidence]:
                raise ValueError("component source evidence mismatch")
            if record["path"] in inputs and inputs[record["path"]] != checksum:
                raise ValueError("conflicting source evidence")
            inputs[record["path"]] = checksum
            records.append(record)
        retained["semantic_dimensions"]["occurrences"] = records
    identities, occurrences = set(), []
    for row in records:
        if row["path"] not in oracle["files"] or row["root"] != str(Path(row["path"]).parent):
            raise ValueError("unexpected synthetic root/path")
        if inputs[row["path"]] != oracle["files"][row["path"]]["sha256"]:
            raise ValueError("source bytes not bound")
        identities.add(row["package"])
        occurrences.append((row["root"], row["package"]))
    expected = oracle["expected"]
    if (
        len(identities) != expected["identities"]
        or len(occurrences) != expected["occurrences"]
        or hash_records(identities) != expected["identities_sha256"]
        or hash_records(occurrences) != expected["occurrences_sha256"]
    ):
        raise ValueError("synthetic selected identities or root occurrences disagree")
    # Normalize only occurrence ordering changed by component bom-ref sorting;
    # every other typed inventory fact must survive the standard export.
    retained["semantic_dimensions"]["occurrences"] = sorted(records, key=lambda row: json.dumps(row, sort_keys=True))
    inventory_sha256 = hashlib.sha256(
        json.dumps(retained, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    return {
        "status": "exact-synthetic-pin-identities-and-roots",
        "identities": len(identities),
        "occurrences": len(occurrences),
        "canonical_inventory_sha256": inventory_sha256,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--oracle", required=True, type=Path)
    parser.add_argument("--mode", required=True, choices=["direct-inventory", "direct-cyclonedx"])
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    if args.raw.stat().st_size > 64 * 1024 * 1024 or args.oracle.stat().st_size > 1024 * 1024:
        raise ValueError("audit input budget exceeded")
    print(json.dumps(audit(decode(args.raw.read_bytes()), decode(args.oracle.read_bytes()), args.mode)))


if __name__ == "__main__":
    main()
