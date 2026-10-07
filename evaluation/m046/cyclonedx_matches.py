"""Recover local Grype source context by exact exported occurrence ID.

This is a controller-internal evaluation API, not imported-BOM admission. The
caller must bind the actual exported bytes, consumer binary/config and DB epoch.
Grype's original artifact/locations and finding metadata remain unchanged.
"""

from copy import deepcopy
import re
import time
from urllib.parse import quote

from .cyclonedx_export import MAX_BYTES, MAX_NODES, PREFIX, check, occurrence_identity, tree_bound, validate
from .static_cli import encode
from .static_inputs import InputRefusal, relative_path
from .syft_control_audit import decode


def properties(record):
    result = {}
    for row in record["properties"]:
        name = row["name"]
        if not name.startswith(PREFIX) or name in result or not isinstance(row.get("value"), str):
            raise ValueError("unadmitted-or-duplicate-export-property")
        result[name] = decode(row["value"])
    return result


def recover(document, report, *, deadline=None):
    deadline = time.monotonic() + 150 if deadline is None else deadline
    validate(document, deadline=deadline)
    tree_bound(report, deadline, string_limit=MAX_BYTES, consumer_floats=True)
    if not isinstance(report.get("matches"), list) or len(report["matches"]) > 500000:
        raise ValueError("invalid-or-oversized-matching-result")
    metadata = properties(document["metadata"])
    inventory = metadata[PREFIX + "inventory"]
    inputs = {r["path"]: r for r in inventory["semantic_dimensions"]["inputs"]}
    if len(inputs) != len(inventory["semantic_dimensions"]["inputs"]):
        raise ValueError("duplicate-export-input")
    bindings = {}
    for component in document["components"]:
        check(deadline)
        values = properties(component)
        occurrence = values[PREFIX + "occurrence"]
        ref = component["bom-ref"]
        path = relative_path(occurrence["path"])
        source = inputs.get(path)
        if (
            source is None
            or not re.fullmatch(r"[0-9a-f]{64}", source.get("sha256") or "")
            or values[PREFIX + "source_sha256"] != source["sha256"]
        ):
            raise ValueError("unbound-export-occurrence-source")
        if (
            occurrence["root"] not in source["roots"]
            or occurrence["root"] not in inventory["semantic_dimensions"]["roots"]
            or occurrence_identity(occurrence) != ref
        ):
            raise ValueError("unbound-export-occurrence-id-or-root")
        package = occurrence["package"]
        name, version = package.removeprefix("pypi:").split("@", 1)
        purl = "pkg:pypi/" + quote(name, safe="") + "@" + quote(version, safe="")
        if not package.startswith("pypi:") or (component["name"], component["version"], component["purl"]) != (
            name,
            version,
            purl,
        ):
            raise ValueError("export-component-selection-mismatch")
        location = component["evidence"]["occurrences"][0]
        expected_location = {"bom-ref": ref + "-evidence", "location": path, "additionalContext": occurrence["locator"]}
        if re.fullmatch(r"line:[1-9][0-9]*", occurrence["locator"]):
            expected_location["line"] = int(occurrence["locator"].split(":")[1])
        if location != expected_location:
            raise ValueError("export-source-evidence-mismatch")
        context = {
            "location_recovery": "exact-exported-occurrence-id",
            "occurrence": occurrence,
            "source_sha256": source["sha256"],
            "activation": occurrence["activation"],
        }
        context_nodes = tree_bound(context, deadline)
        context_bytes = len(encode(context, deadline=deadline)) - 1
        bindings[ref] = (component, context, context_nodes, context_bytes)
    recovered = []
    output_bytes, output_nodes = 3, 1  # JSON array brackets and final newline.
    for match in report["matches"]:
        check(deadline)
        artifact = match["artifact"]
        binding = bindings.get(artifact["id"])
        if binding is None:
            raise ValueError("unknown-matching-occurrence-id")
        component, context, context_nodes, context_bytes = binding
        if artifact.get("type") != "python" or any(
            artifact.get(key) != component[key] for key in ("name", "version", "purl")
        ):
            raise ValueError("matching-artifact-selection-mismatch")
        if "sourcebastion" in match:
            raise ValueError("matching-result-already-contains-source-context")
        match_nodes = tree_bound(match, deadline, string_limit=MAX_BYTES, consumer_floats=True)
        match_bytes = len(encode(match, deadline=deadline)) - 1
        output_nodes += match_nodes + context_nodes + 1
        output_bytes += match_bytes + context_bytes + len(',"sourcebastion":') + (1 if recovered else 0)
        if output_nodes > MAX_NODES or output_bytes > MAX_BYTES:
            raise InputRefusal("matching-context-output-budget-exceeded")
        item = deepcopy(match)
        item["sourcebastion"] = deepcopy(context)
        recovered.append(item)
    return recovered
