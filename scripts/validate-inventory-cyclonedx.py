"""Trusted offline host gate over retained installed/native generated SBOMs."""

import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys

PREFIX = "sourcebastion:inventory:"
SCOPE_LOSS = "cyclonedx-default-required-scope-unassessed"


def render(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def properties(rows):
    return sorted(
        ({"name": PREFIX + name, "value": render(value).decode()} for name, value in rows),
        key=lambda row: (row["name"], row["value"]),
    )


def check_binding(case, schemas):
    """Compare exact retained canonical facts, independent of format validity."""
    document, inventory = case["document"], case["inventory"]
    assert set(document) <= {
        "bomFormat",
        "specVersion",
        "version",
        "metadata",
        "components",
        "dependencies",
        "compositions",
    }
    assert document["bomFormat"] == "CycloneDX" and document["specVersion"] == "1.6" and document["version"] == 1
    assert inventory["schema_version"] == "sourcebastion.inventory/1" and inventory["stages"]["inventory"] != "failed"
    assert hashlib.sha256(render(document)).hexdigest() == case["bom_sha256"]
    assert hashlib.sha256(render(inventory)).hexdigest() == case["inventory_sha256"]
    context = {
        "exporter": "sourcebastion.cyclonedx/1",
        "specification": "1.6",
        "schemas": schemas,
        "inventory_sha256": case["inventory_sha256"],
        "source_sha256": inventory["source_sha256"],
        "producer": inventory["producer"],
        "environment_sha256": inventory["environment_sha256"],
    }
    assert hashlib.sha256(render(context)).hexdigest() == case["identity_sha256"]
    expected = {
        row["id"]: row
        for row in inventory["occurrences"]
        if row["selected_version"] is not None and row["purl"] is not None
    }
    assert len(expected) == len(document["components"])
    assert {row["bom-ref"] for row in document["components"]} == set(expected)
    for component in document["components"]:
        row = expected[component["bom-ref"]]
        assert set(component) == {"type", "bom-ref", "name", "version", "purl", "evidence", "properties"}
        assert component["type"] == "library"
        assert (component["name"], component["version"], component["purl"]) == (
            row["name"],
            row["selected_version"],
            row["purl"],
        )
        assert component["properties"] == properties([("occurrence", row), ("projection-losses", [SCOPE_LOSS])])
        source = row["source"]
        evidence = {"location": source["path"], "additionalContext": source["locator"]}
        import re

        if re.fullmatch(r"line:[1-9][0-9]*", source["locator"]):
            evidence["line"] = int(source["locator"].split(":")[1])
        assert component["evidence"] == {"occurrences": [evidence]}
    rows = [("export", context), ("environment", inventory["environment"]), ("limits", inventory["limits"])]
    rows.append(("coverage", {key: value for key, value in inventory["coverage"].items() if key != "inputs"}))
    rows += [
        ("stages", inventory["stages"]),
        ("graph-policy", "evidenced-unconditional-subset; absence-unreported"),
        ("scope-policy", "standard-default-required-is-unassessed; canonical-scopes-authoritative"),
    ]
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
        rows.extend((field, row) for row in inventory[field])
    rows.extend(("input", row) for row in inventory["coverage"]["inputs"])
    unexported = [row for row in inventory["occurrences"] if row["id"] not in expected]
    rows.extend(("unexported-occurrence", row) for row in unexported)
    edges, lost = {}, []
    for edge in inventory["relationships"]:
        endpoints = [expected.get(edge[key]) for key in ("parent_id", "child_id")]
        admitted = (
            all(row is not None for row in endpoints)
            and edge["evidence_status"] == "evidenced"
            and edge["activation"] == "active"
            and not edge["marker"]
            and not edge["extras"]
            and all(row["activation"] == "active" and not row["marker"] and not row["extras"] for row in endpoints)
        )
        if admitted:
            edges.setdefault(edge["parent_id"], set()).add(edge["child_id"])
        else:
            lost.append(edge)
            rows.append(("unexported-relationship", {"id": edge["id"], "reason": "conditional-or-unassessed-edge"}))
    if edges:
        assert document["dependencies"] == [
            {"ref": key, "dependsOn": sorted(value)} for key, value in sorted(edges.items())
        ]
    else:
        assert "dependencies" not in document
    assert case["omitted_occurrences"] == len(unexported)
    assert case["omitted_relationships"] == len(lost)
    assert case["scope_losses"] == len(expected)
    rows.append(
        (
            "projection",
            {
                "omitted_occurrences": len(unexported),
                "omitted_relationships": len(lost),
                "unassessed_component_scopes": len(expected),
            },
        )
    )
    assert document["metadata"] == {"properties": properties(rows)}
    assert document["compositions"] == [{"aggregate": "unknown"}]


def validate(path):
    if sys.flags.optimize:
        raise RuntimeError("optimized-probe-runtime-refused")
    from jsonschema import Draft7Validator, FormatChecker
    from referencing import Registry, Resource

    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("native-proof-byte-budget-exceeded")
    content = path.read_bytes()
    proof = json.loads(content)
    assert proof["schema_version"] == "sourcebastion.cyclonedx-native-proof/1"
    assert proof["status"] == "native-installed-cyclonedx-generated" and len(proof["cases"]) == 8
    assert len({row["case"] for row in proof["cases"]}) == 8
    root = Path("evaluation/m046/cyclonedx-schemas")
    pins = json.loads((root / "pins.json").read_bytes())
    assert set(proof["schemas"]) == {"bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"}
    registry, documents = (
        Registry(retrieve=lambda uri: (_ for _ in ()).throw(ValueError("remote-schema-retrieval-refused"))),
        {},
    )
    for name, checksum in proof["schemas"].items():
        raw = (root / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == checksum == pins["files"][name]["sha256"]
        schema = json.loads(raw)
        documents[name] = schema
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    validator = Draft7Validator(documents["bom-1.6.schema.json"], registry=registry, format_checker=FormatChecker())
    for name, checksum in proof["source_modules"].items():
        assert name.startswith("sourcebastion/inventory/") and ".." not in Path(name).parts
        assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == checksum
    for case in proof["cases"]:
        document, inventory = case["document"], case["inventory"]
        assert hashlib.sha256(render(document)).hexdigest() == case["bom_sha256"]
        assert hashlib.sha256(render(inventory)).hexdigest() == case["inventory_sha256"]
        validator.validate(document)
        check_binding(case, proof["schemas"])
        expected = {
            row["id"]: row
            for row in inventory["occurrences"]
            if row["selected_version"] is not None and row["purl"] is not None
        }
        assert {row["bom-ref"] for row in document["components"]} == set(expected)
        assert len(document["components"]) == len(expected)
        for component in document["components"]:
            row = expected[component["bom-ref"]]
            assert (component["name"], component["version"], component["purl"]) == (
                row["name"],
                row["selected_version"],
                row["purl"],
            )
            assert component["evidence"]["occurrences"][0]["location"] == row["source"]["path"]
        assert document["compositions"] == [{"aggregate": "unknown"}]
    versions = {
        name: importlib.metadata.version(name)
        for name in ("jsonschema", "referencing", "attrs", "rpds-py", "jsonschema-specifications")
    }
    print(
        json.dumps(
            {
                "status": "offline-official-cyclonedx-validation-passed",
                "native_proof_sha256": hashlib.sha256(content).hexdigest(),
                "cases": 8,
                "schemas": proof["schemas"],
                "validator_versions": versions,
                "scope": "host official-schema validation over exact installed emitted bytes; no matching or imported-BOM admission",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    try:
        if sys.flags.optimize:
            raise RuntimeError("optimized-probe-runtime-refused")
        validate(Path(sys.argv[1]))
    except Exception as error:
        print(json.dumps({"status": "offline-official-cyclonedx-validation-failed", "reason": type(error).__name__}))
        raise
