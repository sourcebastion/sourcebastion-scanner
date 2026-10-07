"""Bounded post-measurement audit of synthetic Syft pin identities and roots."""

import argparse
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import resource


def hash_records(records):
    return hashlib.sha256(json.dumps(sorted(records), separators=(",", ":")).encode()).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("nonfinite JSON constant: " + value)


def decode(content):
    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("nonfinite JSON number")
        return number

    return json.loads(
        content, object_pairs_hook=unique_object, parse_constant=reject_constant, parse_float=finite_float
    )


def audit(document, oracle):
    artifacts = document["artifacts"]
    identities, occurrences, identifiers = set(), [], set()
    cpes = 0
    for record in artifacts:
        identifier = record["id"]
        if not isinstance(identifier, str) or not identifier or identifier in identifiers:
            raise ValueError("duplicate or invalid artifact ID")
        identifiers.add(identifier)
        name, version = record["name"], record["version"]
        if record["type"] != "python" or record["purl"] != f"pkg:pypi/{name}@{version}":
            raise ValueError("unexpected package representation")
        identity = f"pypi:{name}@{version}"
        identities.add(identity)
        locations = record["locations"]
        if len(locations) != 1:
            raise ValueError("expected one evidenced source location per synthetic pin")
        path = locations[0]["path"]
        if not isinstance(path, str) or not path.startswith("/") or ".." in path.split("/"):
            raise ValueError("unexpected source location")
        relative = path.removeprefix("/")
        if relative not in oracle["files"] or PurePosixPath(relative).name != "requirements.txt":
            raise ValueError("location is not a generated requirements input")
        occurrences.append((str(PurePosixPath(relative).parent), identity))
        if not isinstance(record.get("cpes", []), list):
            raise ValueError("invalid CPE representation")
        cpes += len(record.get("cpes", []))
        # Mutate this isolated child-owned decoded document, avoiding a second
        # whole-document copy. Descriptor deliberately records the toggle.
        record.pop("cpes", None)
    expected = oracle["expected"]
    if (
        len(identities) != expected["identities"]
        or len(occurrences) != expected["occurrences"]
        or hash_records(identities) != expected["identities_sha256"]
        or hash_records(occurrences) != expected["occurrences_sha256"]
    ):
        raise ValueError("synthetic identities or root-aware occurrences disagree with oracle")
    document.pop("descriptor", None)
    for key in ("artifacts", "artifactRelationships", "files"):
        if isinstance(document.get(key), list):
            document[key].sort(key=lambda row: json.dumps(row, sort_keys=True))
    normalized = hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "status": "exact-synthetic-pin-identities-and-roots",
        "identities": len(identities),
        "occurrences": len(occurrences),
        "cpes": cpes,
        "non_cpe_document_sha256": normalized,
        "scope": "synthetic pins only; no general graph, environment or whole-repository coverage claim",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--oracle", type=Path, required=True)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    content = args.raw.read_bytes() if args.raw.stat().st_size <= 64 * 1024 * 1024 else None
    if content is None:
        raise ValueError("raw output exceeds 64MiB")
    print(json.dumps(audit(decode(content), decode(args.oracle.read_text()))))


if __name__ == "__main__":
    main()
