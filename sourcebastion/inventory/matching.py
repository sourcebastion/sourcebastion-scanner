"""Recover canonical source context from a controller-admitted Grype report.

This module does not execute Grype or authenticate the controller's artifact
assertions. It admits only the generated canonical export, preserves original
finding bytes, and never joins occurrences by equal names or purls.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import time

from .contract import Inventory, Record, SHA256, Name, Text, canonical_bytes
from .cyclonedx import Artifact, _bound, export
from .inputs import InputRefusal

VERSION = "sourcebastion.match-recovery/1"
TYPES = {
    "pypi": "python",
    "npm": "npm",
    "golang": "go-module",
    "cargo": "rust-crate",
    "maven": "java-archive",
    "nuget": "dotnet",
    "gem": "gem",
    "composer": "php-composer",
}


class Consumer(Record):
    """Trusted controller assertions, never read from customer configuration."""

    binary_sha256: SHA256
    version: Name
    config_sha256: SHA256
    advisory_snapshot_sha256: SHA256
    advisory_schema: Name
    advisory_built: Text


@dataclass(frozen=True)
class MatchBinding:
    ordinal: int
    occurrence_id: str
    match_sha256: str


@dataclass(frozen=True)
class Recovery:
    original_output: bytes
    output_sha256: str
    inventory_sha256: str
    sbom_sha256: str
    identity_sha256: str
    matches: tuple[MatchBinding, ...]
    # Unique source contexts avoid duplicating large evidence per advisory.
    occurrence_contexts: tuple[tuple[str, bytes], ...]
    matching: str = "succeeded"


def _render(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _decode(raw, limits, deadline, guard):
    if type(raw) is not bytes or not raw or len(raw) > limits.diagnostic_file_bytes:
        raise InputRefusal("matching-report-byte-budget-exceeded")
    depth, quoted, escaped = 0, False, False
    for offset, byte in enumerate(raw):
        if offset % 4096 == 0:
            guard()
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
            if depth > limits.export_depth:
                raise InputRefusal("matching-report-depth-budget-exceeded")
        elif byte in (93, 125):
            depth -= 1

    def pairs(rows):
        value = {}
        for key, child in rows:
            if key in value:
                raise ValueError("duplicate-matching-json-key")
            value[key] = child
        return value

    def constant(_value):
        raise ValueError("nonfinite-matching-json")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
        _bound(value, limits, deadline=deadline, check=guard)
    except InputRefusal:
        raise
    except (UnicodeError, RecursionError, ValueError):
        raise ValueError("invalid-matching-report") from None
    guard()
    return value


def recover(inventory, artifact, raw, *, consumer, deadline, check):
    """Bind report identities and attach source evidence without state mutation.

    The controller must establish successful complete execution, immutable
    binary/config/advisory custody and shared kernel resource isolation before
    passing the report. This function cannot infer those facts from JSON.
    Failure leaves the original Inventory and generated Artifact intact.
    """
    if not isinstance(inventory, Inventory) or type(artifact) is not Artifact or not callable(check):
        raise TypeError("controller-bound-inventory-artifact-and-ledger-required")
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise ValueError("invalid-controller-deadline")

    def guard():
        check()
        if time.monotonic() > deadline:
            raise InputRefusal("matching-recovery-deadline-exceeded")

    guard()
    consumer = Consumer.model_validate(consumer)
    # Re-export rather than trust a forgeable dataclass digest/count receipt.
    expected = export(inventory, deadline=deadline, check=check)
    if artifact != expected:
        raise ValueError("matching-artifact-canonical-binding-mismatch")
    canonical = canonical_bytes(inventory)
    if _sha(canonical) != expected.inventory_sha256:
        raise ValueError("changed-matching-canonical-inventory")
    value = json.loads(canonical)
    limits = inventory.limits
    report = _decode(raw, limits, deadline, guard)
    if type(report) is not dict or type(report.get("matches")) is not list:
        raise ValueError("invalid-matching-report-shape")
    source = report.get("source")
    if type(source) is not dict or source.get("type") != "sbom-file":
        raise ValueError("matching-requires-explicit-sbom-source")
    descriptor = report.get("descriptor")
    if (
        type(descriptor) is not dict
        or descriptor.get("name") != "grype"
        or descriptor.get("version") != consumer.version
    ):
        raise ValueError("matching-consumer-identity-mismatch")
    database = descriptor.get("db")
    status = database.get("status") if type(database) is dict else None
    if (
        type(status) is not dict
        or status.get("valid") is not True
        or status.get("schemaVersion") != consumer.advisory_schema
        or status.get("built") != consumer.advisory_built
    ):
        raise ValueError("matching-advisory-identity-mismatch")
    if len(report["matches"]) > 100000:
        raise InputRefusal("matching-count-budget-exceeded")
    selected = {
        row["id"]: row
        for row in value["occurrences"]
        if row["selected_version"] is not None and row["purl"] is not None
    }
    bindings, contexts, context_bytes = [], {}, 0
    for ordinal, match in enumerate(report["matches"]):
        guard()
        if (
            type(match) is not dict
            or type(match.get("artifact")) is not dict
            or type(match.get("vulnerability")) is not dict
        ):
            raise ValueError("invalid-matching-record")
        observed = match["artifact"]
        identifier = observed.get("id")
        if type(identifier) is not str or identifier not in selected:
            raise ValueError("unknown-matching-occurrence")
        row = selected[identifier]
        if (observed.get("type"), observed.get("name"), observed.get("version"), observed.get("purl")) != (
            TYPES[row["ecosystem"]],
            row["name"],
            row["selected_version"],
            row["purl"],
        ):
            raise ValueError("contradictory-matching-occurrence")
        vulnerability = match["vulnerability"]
        if any(
            type(vulnerability.get(key)) is not str or not vulnerability[key] for key in ("id", "namespace", "severity")
        ):
            raise ValueError("invalid-matching-vulnerability")
        if identifier not in contexts:
            encoded = _render(row)
            context_bytes += len(encoded)
            if context_bytes > limits.diagnostic_file_bytes:
                raise InputRefusal("matching-context-byte-budget-exceeded")
            contexts[identifier] = encoded
        bindings.append(MatchBinding(ordinal, identifier, _sha(_render(match))))
    guard()
    identity = {
        "schema_version": VERSION,
        "inventory_sha256": expected.inventory_sha256,
        "sbom_sha256": expected.sha256,
        "export_identity_sha256": expected.identity_sha256,
        "output_sha256": _sha(raw),
        "consumer": consumer.model_dump(mode="json"),
        "environment_policy": "canonical-activation-and-scopes-authoritative",
    }
    return Recovery(
        raw,
        _sha(raw),
        expected.inventory_sha256,
        expected.sha256,
        _sha(_render(identity)),
        tuple(bindings),
        tuple(sorted(contexts.items())),
    )
