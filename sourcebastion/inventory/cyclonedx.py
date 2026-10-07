"""Generated-only CycloneDX 1.6 profile over canonical source authority.

This is not imported-BOM admission. Standard dependency edges are an evidenced,
unconditional subset; omitted edges never prove dependency absence. Official
offline schema validation of emitted artifacts is a separate release check.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import re
import time

from .contract import Inventory, InventoryLimits, Record, canonical_bytes
from .inputs import InputRefusal

VERSION = "sourcebastion.cyclonedx/1"
SPEC = "1.6"
PREFIX = "sourcebastion:inventory:"
SCHEMAS = {
    "bom-1.6.schema.json": "3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93",
    "spdx.schema.json": "baa9d3bd1ed57b6751b0887edead6b5063ff53ff7429cf85d476c6c94af0166e",
    "jsf-0.82.schema.json": "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
}


@dataclass(frozen=True)
class Artifact:
    """One fully buffered local export; original Inventory stays authoritative."""

    content: bytes
    sha256: str
    inventory_sha256: str
    identity_sha256: str
    omitted_occurrences: int
    omitted_relationships: int
    scope_losses: int
    exporter: str = VERSION
    specification: str = SPEC


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _digest(value):
    return hashlib.sha256(value).hexdigest()


def _guard(deadline, check):
    check()
    if time.monotonic() > deadline:
        raise InputRefusal("sbom-export-deadline-exceeded")


def _record_values(record):
    for field in type(record).model_fields:
        yield getattr(record, field)


def _bound(value, limits, deadline, check):
    # Lazy iterators avoid allocating all children before charging their nodes.
    stack, nodes = [(iter((value,)), 0)], 0
    while stack:
        _guard(deadline, check)
        iterator, depth = stack[-1]
        try:
            item = next(iterator)
        except StopIteration:
            stack.pop()
            continue
        nodes += 1
        if nodes > limits.export_nodes or depth > limits.export_depth:
            raise InputRefusal("sbom-export-structure-budget-exceeded")
        if type(item) is str:
            if len(item) > limits.export_string_bytes or len(item.encode()) > limits.export_string_bytes:
                raise InputRefusal("sbom-export-string-budget-exceeded")
        elif isinstance(item, Record):
            fields = type(item).model_fields
            if nodes + len(fields) > limits.export_nodes:
                raise InputRefusal("sbom-export-structure-budget-exceeded")
            stack.append((_record_values(item), depth + 1))
        elif type(item) in {dict, list, tuple}:
            count = len(item) * (2 if type(item) is dict else 1)
            if nodes + count > limits.export_nodes:
                raise InputRefusal("sbom-export-structure-budget-exceeded")
            if type(item) is dict:

                def values(mapping=item):
                    for key, child in mapping.items():
                        if type(key) is not str:
                            raise ValueError("invalid-sbom-object-key")
                        yield key
                        yield child

                children = values()
            else:
                children = iter(item)
            stack.append((children, depth + 1))
        elif type(item) is float and math.isfinite(item):
            pass
        elif item is not None and type(item) not in {bool, int}:
            raise ValueError("invalid-generated-sbom-value")


def _properties(rows, limits, deadline, check):
    result = []
    for name, value in rows:
        _guard(deadline, check)
        _bound(value, limits, deadline, check)
        rendered = _json(value)
        if len(rendered) > limits.export_string_bytes:
            raise InputRefusal("sbom-export-string-budget-exceeded")
        result.append({"name": PREFIX + name, "value": rendered})
    return sorted(result, key=lambda row: (row["name"], row["value"]))


def export(inventory, *, deadline, check):
    """Export exact canonical occurrences without rescanning or state promotion.

    Controller supplies a shared deadline/semantic ledger and kernel resource
    boundary. Cooperative checks alone cannot contain schema/parser CPU work.
    No executable, callback from customer config, registry or forge API is used.
    """
    if not isinstance(inventory, Inventory) or not callable(check):
        raise TypeError("controller-bound-inventory-and-ledger-required")
    if type(deadline) not in {int, float} or not math.isfinite(deadline):
        raise ValueError("invalid-controller-deadline")
    _guard(deadline, check)
    limits = InventoryLimits.model_validate(inventory.limits)
    # Includes preflight and strict reference/authority revalidation, before
    # copying nested objects or granting any occurrence selected-version power.
    _bound(inventory, limits, deadline, check)
    encoded_inventory = canonical_bytes(inventory)
    _guard(deadline, check)
    data = json.loads(encoded_inventory)
    if data["stages"]["inventory"] == "failed":
        raise ValueError("failed-inventory-cannot-be-exported")
    inventory_sha = _digest(encoded_inventory)
    context = {
        "exporter": VERSION,
        "specification": SPEC,
        "schemas": SCHEMAS,
        "inventory_sha256": inventory_sha,
        "source_sha256": data["source_sha256"],
        "producer": data["producer"],
        "environment_sha256": data["environment_sha256"],
    }
    identity = _digest(_json(context).encode())
    metadata = [("export", context), ("environment", data["environment"]), ("limits", data["limits"])]
    metadata += [("coverage", {key: value for key, value in data["coverage"].items() if key != "inputs"})]
    metadata += [("stages", data["stages"]), ("graph-policy", "evidenced-unconditional-subset; absence-unreported")]
    metadata.append(("scope-policy", "standard-default-required-is-unassessed; canonical-scopes-authoritative"))
    for field in (
        "roots",
        "analysis_scopes",
        "installed_environments",
        "applications",
        "losses",
        "declarations",
        "input_references",
        "applicability",
        "dependency_selectors",
        "relationships",
    ):
        metadata.extend((field, row) for row in data[field])
    metadata.extend(("input", row) for row in data["coverage"]["inputs"])
    components, selected, omitted = [], {}, 0
    for row in data["occurrences"]:
        _guard(deadline, check)
        if row["selected_version"] is None or row["purl"] is None:
            omitted += 1
            metadata.append(("unexported-occurrence", row))
            continue
        source = row["source"]
        occurrence = {"location": source["path"], "additionalContext": source["locator"]}
        if re.fullmatch(r"line:[1-9][0-9]*", source["locator"]):
            occurrence["line"] = int(source["locator"].split(":")[1])
        # Retain canonical namespace/name in purl. CycloneDX's display name
        # carries the same asserted canonical name, not an inferred project.
        component = {
            "type": "library",
            "bom-ref": row["id"],
            "name": row["name"],
            "version": row["selected_version"],
            "purl": row["purl"],
            "evidence": {"occurrences": [occurrence]},
            "properties": _properties(
                [("occurrence", row), ("projection-losses", ["cyclonedx-default-required-scope-unassessed"])],
                limits,
                deadline,
                check,
            ),
        }
        components.append(component)
        selected[row["id"]] = row
    adjacency, omitted_edges = {}, 0
    for edge in data["relationships"]:
        _guard(deadline, check)
        parent, child = selected.get(edge["parent_id"]), selected.get(edge["child_id"])
        if (
            parent is None
            or child is None
            or edge["evidence_status"] != "evidenced"
            or edge["activation"] != "active"
            or edge["marker"]
            or edge["extras"]
            or any(row["activation"] != "active" or row["marker"] or row["extras"] for row in (parent, child))
        ):
            omitted_edges += 1
            metadata.append(("unexported-relationship", {"id": edge["id"], "reason": "conditional-or-unassessed-edge"}))
            continue
        adjacency.setdefault(edge["parent_id"], set()).add(edge["child_id"])
    metadata.append(
        (
            "projection",
            {
                "omitted_occurrences": omitted,
                "omitted_relationships": omitted_edges,
                "unassessed_component_scopes": len(components),
            },
        )
    )
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC,
        "version": 1,
        "metadata": {"properties": _properties(metadata, limits, deadline, check)},
        "components": components,
        "compositions": [{"aggregate": "unknown"}],
    }
    if adjacency:
        document["dependencies"] = [
            {"ref": key, "dependsOn": sorted(value)} for key, value in sorted(adjacency.items())
        ]
    _bound(document, limits, deadline, check)
    chunks, size = [], 0
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    for chunk in encoder.iterencode(document):
        _guard(deadline, check)
        raw = chunk.encode()
        size += len(raw)
        if size > limits.sbom_bytes:
            raise InputRefusal("sbom-export-byte-budget-exceeded")
        chunks.append(raw)
    content = b"".join(chunks)
    _guard(deadline, check)
    return Artifact(content, _digest(content), inventory_sha, identity, omitted, omitted_edges, len(components))
