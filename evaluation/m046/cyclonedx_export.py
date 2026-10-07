"""Engine-neutral, finite-scope CycloneDX export experiment; no source rescan.

The input is the controller-produced static inventory, not an imported SBOM.
Properties preserve declaration semantics that CycloneDX/Grype do not interpret.
An exported dependency subset never asserts that omitted dependencies are absent.
"""

from collections import defaultdict
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import re
import time
from urllib.parse import quote

from jsonschema import Draft7Validator, FormatChecker, ValidationError, validators
from referencing import Registry, Resource

from .static_cli import encode
from .static_inputs import InputRefusal, relative_path
from .static_inventory import VERSION as INVENTORY_VERSION

VERSION = "m046-cyclonedx-evaluation-v1"
MAX_BYTES = 64 * 1024 * 1024
MAX_NODES = 2000000
MAX_COMPONENTS = 100000
MAX_RELATIONSHIPS = 500000
PREFIX = "sourcebastion:m046:"
SCHEMAS = {
    "bom-1.6.schema.json": "3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93",
    "spdx.schema.json": "baa9d3bd1ed57b6751b0887edead6b5063ff53ff7429cf85d476c6c94af0166e",
    "jsf-0.82.schema.json": "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def identity(value):
    return "m046-" + hashlib.sha256(canonical(value).encode("ascii")).hexdigest()


def occurrence_identity(record):
    # Preserve the already reviewed cross-format occurrence namespace and Go
    # encoding (UTF8 plus HTML/JS separators), not Python's ensure_ascii form.
    content = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    for character, escaped in [
        ("<", r"\u003c"),
        (">", r"\u003e"),
        ("&", r"\u0026"),
        ("\u2028", r"\u2028"),
        ("\u2029", r"\u2029"),
    ]:
        content = content.replace(character, escaped)
    return (
        "m046-"
        + hashlib.sha256(
            b"m046-syft-occurrence-v1\0m046-static-inventory-prototype-v5\0" + content.encode("utf-8")
        ).hexdigest()
    )


def check(deadline):
    if time.monotonic() > deadline:
        raise InputRefusal("sbom-export-deadline-exceeded")


def tree_bound(value, deadline, *, string_limit=2 * 1024 * 1024, consumer_floats=False):
    """Bound before copy/serialization; reject cycles, exotic objects and floats."""
    stack = [(value, 0)]
    containers, nodes, text_bytes = set(), 0, 0
    while stack:
        check(deadline)
        node, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > 32:
            raise InputRefusal("sbom-input-complexity-exceeded")
        if type(node) in {dict, list, tuple}:
            if id(node) in containers:
                raise ValueError("shared-or-cyclic-inventory-container")
            containers.add(id(node))
            child_count = len(node) * (2 if isinstance(node, dict) else 1)
            if nodes + len(stack) + child_count > MAX_NODES:
                raise InputRefusal("sbom-input-complexity-exceeded")
            if isinstance(node, dict):
                if any(type(key) is not str for key in node):
                    raise ValueError("non-string-inventory-key")
                stack.extend((key, depth + 1) for key in node)
                stack.extend((item, depth + 1) for item in node.values())
            else:
                stack.extend((item, depth + 1) for item in node)
        elif type(node) is str:
            if len(node) > string_limit:
                raise InputRefusal("sbom-input-text-exceeded")
            text_bytes += len(node.encode("utf-8"))
            if text_bytes > MAX_BYTES:
                raise InputRefusal("sbom-input-text-exceeded")
        elif consumer_floats and type(node) is float:
            if not math.isfinite(node):
                raise ValueError("nonfinite-consumer-value")
        elif node is not None and type(node) not in {bool, int}:
            raise ValueError("unsupported-inventory-value")
    return nodes


def properties(values):
    return [{"name": PREFIX + key, "value": canonical(value)} for key, value in sorted(values.items())]


def _deny_remote(uri):
    raise ValueError("remote-schema-retrieval-refused")


def unique_items(validator, required, instance, schema):
    """Linear exact uniqueness for our bounded JSON profile (floats refused).

    Canonical JSON distinguishes booleans/integers, normalizes object key order
    and array containers. Retain complete canonical values: no hash collisions
    can authorize a duplicate. The official dict fallback is quadratic.
    """
    if not required or not validator.is_type(instance, "array"):
        return
    seen = set()
    for value in instance:
        rendered = canonical(value)
        if rendered in seen:
            yield ValidationError("duplicate array value")
            return
        seen.add(rendered)


BoundedValidator = validators.extend(Draft7Validator, {"uniqueItems": unique_items})


def validator():
    registry = Registry(retrieve=_deny_remote)
    documents = {}
    for filename, expected in SCHEMAS.items():
        content = (Path(__file__).parent / "schemas" / filename).read_bytes()
        if hashlib.sha256(content).hexdigest() != expected:
            raise ValueError("pinned-schema-digest-mismatch")
        schema = json.loads(content)
        documents[filename] = schema
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return BoundedValidator(documents["bom-1.6.schema.json"], registry=registry, format_checker=FormatChecker())


def validate(document, *, deadline=None):
    """Offline schema plus identity/reference checks, under caller resource limits.

    Schema evaluation itself requires an outer process deadline/CPU/AS limit for
    hostile or very large inputs; cooperative checks are not a production jail.
    """
    deadline = time.monotonic() + 150 if deadline is None else deadline
    tree_bound(document, deadline, string_limit=MAX_BYTES)
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.6":
        raise ValueError("unadmitted-sbom-format-version")
    # Admit only this serializer's flat profile; recursive/imported BOMs and
    # unrelated reference-bearing fields need their own reviewed admission.
    if set(document) - {
        "bomFormat",
        "specVersion",
        "version",
        "metadata",
        "components",
        "dependencies",
        "compositions",
    }:
        raise ValueError("unadmitted-sbom-field")
    if set(document.get("metadata", {})) != {"properties"}:
        raise ValueError("unadmitted-sbom-metadata")
    for component in document.get("components", []):
        if set(component) != {"type", "bom-ref", "name", "version", "purl", "evidence", "properties"}:
            raise ValueError("unadmitted-component-profile")
        if component["type"] != "library":
            raise ValueError("unadmitted-component-type")
        if set(component["evidence"]) != {"occurrences"} or len(component["evidence"]["occurrences"]) != 1:
            raise ValueError("unadmitted-component-evidence")
        if set(component["evidence"]["occurrences"][0]) - {"bom-ref", "location", "line", "additionalContext"}:
            raise ValueError("unadmitted-occurrence-evidence")
    for edge in document.get("dependencies", []):
        if set(edge) != {"ref", "dependsOn"}:
            raise ValueError("unadmitted-dependency-profile")
    if document.get("compositions") != [{"aggregate": "unknown"}]:
        raise ValueError("unadmitted-composition-profile")
    validator().validate(document)
    check(deadline)
    refs = set()
    for component in document.get("components", []):
        check(deadline)
        for ref in [
            component["bom-ref"],
            *[r["bom-ref"] for r in component.get("evidence", {}).get("occurrences", [])],
        ]:
            if ref in refs:
                raise ValueError("duplicate-bom-ref")
            refs.add(ref)
    component_refs = {record["bom-ref"] for record in document.get("components", [])}
    parents = set()
    for edge in document.get("dependencies", []):
        check(deadline)
        if edge["ref"] in parents or edge["ref"] not in component_refs:
            raise ValueError("invalid-dependency-parent")
        parents.add(edge["ref"])
        if not set(edge.get("dependsOn", [])) <= component_refs:
            raise ValueError("dangling-dependency-reference")


def export(inventory, *, provenance, limit=MAX_BYTES, deadline=None):
    """Return fully buffered validated bytes without mutating the input statuses.

    Successful serialization leaves inventory partial/failed facts untouched and
    does not start vulnerability matching. No clocks/random IDs enter identity.
    """
    deadline = time.monotonic() + 150 if deadline is None else deadline
    tree_bound(inventory, deadline)
    tree_bound(provenance, deadline)
    if inventory.get("schema_version") != INVENTORY_VERSION or inventory.get("inventory_status") not in {
        "complete",
        "partial",
    }:
        raise ValueError("unadmitted-inventory-contract-or-status")
    if set(provenance) != {"producer", "code_sha256", "registry_sha256", "config_sha256", "environment_policy"}:
        raise ValueError("incomplete-export-provenance")
    if any(not isinstance(provenance[key], str) or not provenance[key] for key in provenance):
        raise ValueError("invalid-export-provenance")
    if any(not re.fullmatch(r"[0-9a-f]{64}", provenance[key]) for key in provenance if key.endswith("_sha256")):
        raise ValueError("invalid-export-provenance-digest")
    dimensions = inventory["semantic_dimensions"]
    occurrences = dimensions["occurrences"]
    relationships = dimensions["relationships"]
    if len(occurrences) > MAX_COMPONENTS or len(relationships) > MAX_RELATIONSHIPS:
        raise InputRefusal("sbom-record-budget-exceeded")
    input_paths = {record["path"]: record for record in dimensions["inputs"]}
    if len(input_paths) != len(dimensions["inputs"]):
        raise ValueError("duplicate-inventory-input")
    for path in input_paths:
        relative_path(path)
    for root in dimensions["roots"]:
        if root != ".":
            relative_path(root)
    components, refs, by_context = [], set(), defaultdict(list)
    for record in occurrences:
        check(deadline)
        relative_path(record["path"])
        source = input_paths.get(record["path"])
        if source is None or not re.fullmatch(r"[0-9a-f]{64}", source.get("sha256") or ""):
            raise ValueError("occurrence-without-content-bound-input")
        if record["root"] not in dimensions["roots"] or record["root"] not in source["roots"]:
            raise ValueError("occurrence-root-not-in-input")
        match = re.fullmatch(r"pypi:([a-z0-9]+(?:-[a-z0-9]+)*)@([^\s@]+)", record["package"])
        if match is None:
            raise ValueError("unadmitted-package-identity")
        name, version = match.groups()
        ref = occurrence_identity(record)
        if ref in refs:
            raise ValueError("duplicate-inventory-occurrence")
        refs.add(ref)
        by_context[(record["root"], record["path"], record["package"])].append((ref, record))
        occurrence = {"bom-ref": ref + "-evidence", "location": record["path"], "additionalContext": record["locator"]}
        if re.fullmatch(r"line:[1-9][0-9]*", record["locator"]):
            occurrence["line"] = int(record["locator"].split(":")[1])
        components.append(
            {
                "type": "library",
                "bom-ref": ref,
                "name": name,
                "version": version,
                "purl": "pkg:pypi/" + quote(name, safe="") + "@" + quote(version, safe=""),
                "evidence": {"occurrences": [occurrence]},
                "properties": properties({"occurrence": record, "source_sha256": source["sha256"]}),
            }
        )
    adjacency, losses, steps = defaultdict(set), [], 0
    conditional_roots = {r["root"] for r in dimensions["environment_records"] if r.get("activation") != "unconditional"}
    for record in relationships:
        check(deadline)
        endpoints = []
        for endpoint in ("parent", "child"):
            candidates = []
            locator = record.get(endpoint + "_locator")
            for ref, occurrence in by_context.get((record["root"], record["path"], record[endpoint]), []):
                check(deadline)
                steps += 1
                if steps > 5000000:
                    raise InputRefusal("sbom-edge-resolution-budget-exceeded")
                if (
                    locator is None
                    or occurrence["locator"] == locator
                    or (endpoint == "child" and occurrence["locator"].startswith(locator + ".groups["))
                ):
                    candidates.append((ref, occurrence))
            endpoints.append(candidates)
        parent, child = endpoints
        reason = None
        if record["kind"] != "dependency":
            reason = "unsupported-relationship-kind"
        elif len(parent) != 1 or len(child) != 1:
            reason = (
                "missing-parent-occurrence"
                if not parent
                else (
                    "ambiguous-parent-occurrence"
                    if len(parent) > 1
                    else "missing-child-occurrence" if not child else "ambiguous-child-occurrence"
                )
            )
        elif (
            record.get("activation", "unconditional") != "unconditional"
            or record.get("marker")
            or record.get("extras")
            or record["root"] in conditional_roots
            or any(
                r.get("activation") != "unconditional" or r.get("marker") or r.get("requires_python")
                for _, r in [parent[0], child[0]]
            )
        ):
            reason = "conditional-or-unknown-edge-context"
        if reason:
            losses.append({"reason": reason, "record": record})
        else:
            adjacency[parent[0][0]].add(child[0][0])
    retained = deepcopy(inventory)
    retained["semantic_dimensions"].pop("occurrences")
    context = {
        "exporter": VERSION,
        "spec": "1.6",
        "schemas": SCHEMAS,
        "provenance": provenance,
        "inventory_contract": INVENTORY_VERSION,
        "input_evidence": dimensions["inputs"],
    }
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "properties": properties(
                {
                    "exporter": VERSION,
                    "inventory": retained,
                    "provenance": provenance,
                    "compatibility_identity": identity(context),
                    "projection_losses": losses,
                    "graph_policy": "evidenced-subset; omitted vertices have unknown dependencies",
                    "inventory_status": inventory["inventory_status"],
                    "sbom_status": "complete",
                    "matching_status": "not-run",
                }
            )
        },
        "components": sorted(components, key=lambda r: r["bom-ref"]),
        "compositions": [{"aggregate": "unknown"}],
    }
    # Missing vertices deliberately stay missing: dependsOn:[] would claim a
    # dependency-free package that a flat declaration cannot establish.
    if adjacency:
        document["dependencies"] = [
            {"ref": ref, "dependsOn": sorted(children)} for ref, children in sorted(adjacency.items())
        ]
    # Bound bytes before schema work; do not emit partial JSON on failure.
    content = encode(document, limit=limit, deadline=deadline)
    validate(document, deadline=deadline)
    return content
