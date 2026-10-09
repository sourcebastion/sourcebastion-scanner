"""Offline maintenance gates over independent expected and observed evidence.

These are maintenance inputs, never customer scan configuration or host custody.
No tool output is promoted to an expected-results oracle.
"""

from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 64 * 1024**2
COLLECTIONS = (
    "roots", "analysis_scopes", "installed_environments", "declarations",
    "input_references", "occurrences", "relationships", "applications", "losses",
    "applicability", "dependency_selectors",
)


def render(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError("upgrade-artifact-byte-limit")
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError("upgrade-duplicate-json-key")
            result[key] = value
        return result
    def constant(_value):
        raise ValueError("upgrade-nonfinite-json")
    # Cap nesting before the standard decoder constructs a tree.
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 64:
                raise ValueError("upgrade-artifact-depth-limit")
        elif byte in (93, 125):
            depth -= 1
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    return value, sha(raw)


def semantic(value):
    """Use located context identities, retaining all fields and multiplicities.

    Producer digests and opaque generated record IDs may change in an upgrade;
    source anchors and every semantic field must still agree. An ambiguous
    anchor refuses comparison instead of guessing ownership by package name.
    """
    helper = runpy.run_path(str(ROOT / "scripts/verify-inventory-expectations.py"))
    anchor, normalize = helper["anchor"], helper["normalize"]
    records = value.get("records", value)
    if not set(COLLECTIONS).issubset(records):
        raise ValueError("upgrade-missing-record-collection")
    aliases, seen = {}, set()
    for collection in COLLECTIONS:
        for row in records[collection]:
            key = collection + ":" + sha(anchor(collection, row, aliases))
            if key in seen or row["id"] in aliases:
                raise ValueError("upgrade-ambiguous-source-anchor")
            seen.add(key)
            aliases[row["id"]] = key
    normalized = {
        collection: sorted((normalize(row, aliases) for row in records[collection]), key=render)
        for collection in COLLECTIONS
    }
    coverage = deepcopy(value["coverage"])
    coverage["inputs"] = sorted((normalize(row, aliases) for row in coverage["inputs"]), key=render)
    occurrences = normalized.pop("occurrences")
    versions = [
        {key: row[key] for key in ("id", "selected_version", "declared_range", "hashes", "purl")}
        for row in occurrences
    ]
    packages = [{key: item for key, item in row.items() if key not in {"selected_version", "declared_range", "hashes", "purl"}}
                for row in occurrences]
    return {
        "packages": packages,
        "versions": versions,
        "edges": normalized.pop("relationships"),
        "coverage": {"summary": coverage, "losses": normalized.pop("losses"), "stages": value["stages"]},
        "context": normalized,
    }


def delta(before, after):
    # Whole-row records retain relationships, roots and qualifiers. Counters
    # prevent duplicate evidence from disappearing in a set comparison.
    left, right = Counter(render(row) for row in before), Counter(render(row) for row in after)
    return {
        "removed": [json.loads(row) for row in sorted((left - right).elements())],
        "added": [json.loads(row) for row in sorted((right - left).elements())],
    }


def corpus_diff(baseline, candidate):
    if type(baseline) is not dict or type(candidate) is not dict:
        raise ValueError("upgrade-evidence-document-required")
    if baseline.get("schema_version") != "m046.canonical-source-expectations/1":
        raise ValueError("upgrade-baseline-must-be-independent-oracle")
    if candidate.get("schema_version") != "m046.canonical-source-expectations-proof/1":
        raise ValueError("upgrade-candidate-must-be-native-proof")
    def cases(rows):
        result = {}
        for row in rows:
            name = row["case"]
            if type(name) is not str or not name or name in result:
                raise ValueError("upgrade-duplicate-or-invalid-case")
            result[name] = row
        if not result:
            raise ValueError("upgrade-empty-corpus")
        return result
    old, new = cases(baseline["cases"]), cases(candidate["cases"])
    changes = []
    for name in sorted(old.keys() & new.keys()):
        before, after = semantic(old[name]), semantic(new[name]["observed"])
        dimensions = {}
        for dimension in before:
            if before[dimension] != after[dimension]:
                if dimension in {"packages", "versions", "edges"}:
                    dimensions[dimension] = delta(before[dimension], after[dimension])
                else:
                    dimensions[dimension] = {"before": before[dimension], "after": after[dimension]}
        if dimensions:
            changes.append({"case": name, "dimensions": dimensions})
    missing, added = sorted(old.keys() - new.keys()), sorted(new.keys() - old.keys())
    same_corpus = baseline["historical_oracle_sha256"] == candidate["historical_oracle_sha256"]
    return {
        "status": "passed" if same_corpus and not (missing or added or changes) else "review-required",
        "same_source_corpus": same_corpus,
        "cases_compared": len(old.keys() & new.keys()),
        "missing_cases": missing, "added_cases": added, "changes": changes,
    }


def finding_diff(before, after, *, baseline_snapshot, candidate_snapshot):
    """Compare complete Grype match rows under an equal admitted advisory hash.

    A changed snapshot is a separate advisory update, not inventory parity.
    Raw report provenance is retained by the caller's artifact hashes.
    """
    for digest in (baseline_snapshot, candidate_snapshot):
        if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("upgrade-advisory-identity-required")
    if baseline_snapshot != candidate_snapshot:
        raise ValueError("upgrade-advisory-snapshot-changed")
    if any(type(report.get("matches")) is not list for report in (before, after)):
        raise ValueError("upgrade-incomplete-matching-evidence")
    changes = delta(before["matches"], after["matches"])
    return {"status": "passed" if not any(changes.values()) else "review-required", **changes}
