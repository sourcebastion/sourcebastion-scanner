"""Standard validation, semantic retention and refusal tests for local export."""

from copy import deepcopy
import json
import socket
import time

import pytest
from jsonschema import Draft7Validator, ValidationError

from evaluation.m046.corpus import CORPUS
from evaluation.m046.cyclonedx_export import BoundedValidator, PREFIX, export, identity, occurrence_identity, validate
from evaluation.m046.cyclonedx_matches import recover
from evaluation.m046.run import materialize, snapshot
from evaluation.m046.static_inputs import InputRefusal, Source
from evaluation.m046.static_inventory import evaluate

PROVENANCE = {
    "producer": "static-python-evaluation-only",
    "code_sha256": "a" * 64,
    "registry_sha256": "b" * 64,
    "config_sha256": "c" * 64,
    "environment_policy": "retain-conditional-unknown-v1",
}


def props(record):
    return {item["name"].removeprefix(PREFIX): json.loads(item["value"]) for item in record["properties"]}


def scan(root):
    with Source(root) as source:
        return evaluate(source)


def inventory(tmp_path, text="pip==26.0.1\n", name="requirements.txt"):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return scan(tmp_path)


@pytest.mark.parametrize("fixture", CORPUS, ids=lambda f: f["id"])
def test_all_corpus_exports_validate_offline_and_preserve_every_existing_semantic_record(
    tmp_path, fixture, monkeypatch
):
    root = tmp_path / "source"
    materialize(fixture, root)
    original_source = snapshot(root)
    observed = scan(root)
    original_inventory = deepcopy(observed)
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: pytest.fail("network access during export"))
    content = export(observed, provenance=PROVENANCE)
    document = json.loads(content)
    validate(document)
    metadata = props(document["metadata"])
    retained = metadata["inventory"]
    recovered_occurrences = [props(c)["occurrence"] for c in document["components"]]
    retained["semantic_dimensions"]["occurrences"] = observed["semantic_dimensions"]["occurrences"]
    assert retained == json.loads(json.dumps(observed))
    assert sorted(recovered_occurrences, key=identity) == sorted(
        observed["semantic_dimensions"]["occurrences"], key=identity
    )
    assert {c["bom-ref"] for c in document["components"]} == {occurrence_identity(r) for r in recovered_occurrences}
    assert metadata["inventory_status"] == observed["inventory_status"]
    assert metadata["sbom_status"] == "complete" and metadata["matching_status"] == "not-run"
    assert observed == original_inventory and snapshot(root) == original_source
    assert export(observed, provenance=PROVENANCE) == content


def test_custom_hidden_files_keep_exact_purls_ids_source_locations_and_conditional_semantics(tmp_path):
    observed = inventory(tmp_path, 'pip==26.0.1; python_version < "3.15"\n', ".github/python-locks/build.txt")
    document = json.loads(export(observed, provenance=PROVENANCE))
    component = document["components"][0]
    record = observed["semantic_dimensions"]["occurrences"][0]
    assert component["purl"] == "pkg:pypi/pip@26.0.1"
    assert component["bom-ref"] == occurrence_identity(record)
    assert component["evidence"]["occurrences"] == [
        {
            "bom-ref": occurrence_identity(record) + "-evidence",
            "location": ".github/python-locks/build.txt",
            "line": 1,
            "additionalContext": "line:1",
        }
    ]
    assert props(component)["occurrence"]["activation"] == "unknown"
    assert "scope" not in component and "hashes" not in component
    assert "dependencies" not in document


def test_ranges_and_constraints_are_retained_without_inventing_matching_components(tmp_path):
    observed = inventory(tmp_path, "pip>=26\n-c constraints.txt\n")
    (tmp_path / "constraints.txt").write_text("requests==2.32.3\n")
    observed = scan(tmp_path)
    document = json.loads(export(observed, provenance=PROVENANCE))
    assert document["components"] == []
    declarations = props(document["metadata"])["inventory"]["semantic_dimensions"]["declaration_records"]
    assert {(r["name"], r["scope"]) for r in declarations} == {("pypi:pip", "unknown"), ("pypi:requests", "constraint")}
    assert props(document["metadata"])["inventory_status"] == "partial"


def test_different_roots_and_repeated_package_versions_remain_distinct_occurrences(tmp_path):
    observed = inventory(tmp_path, "pip==26.0.1\n", "a/requirements.txt")
    (tmp_path / "b").mkdir()
    (tmp_path / "b/requirements.txt").write_text("pip==26.0.1\n")
    document = json.loads(export(scan(tmp_path), provenance=PROVENANCE))
    assert len(document["components"]) == 2
    assert len({r["bom-ref"] for r in document["components"]}) == 2
    assert {props(r)["occurrence"]["root"] for r in document["components"]} == {"a", "b"}


def test_only_unambiguous_evidenced_edges_enter_standard_graph(tmp_path):
    observed = inventory(tmp_path, "pip==26.0.1\nrequests==2.32.3\n")
    relation = {
        "parent": "pypi:pip@26.0.1",
        "child": "pypi:requests@2.32.3",
        "root": ".",
        "path": "requirements.txt",
        "locator": "synthetic-independent-edge",
        "kind": "dependency",
    }
    observed["semantic_dimensions"]["relationships"] = [relation]
    document = json.loads(export(observed, provenance=PROVENANCE))
    by_name = {r["name"]: r["bom-ref"] for r in document["components"]}
    assert document["dependencies"] == [{"ref": by_name["pip"], "dependsOn": [by_name["requests"]]}]
    relation["kind"] = "containment"
    second = json.loads(export(observed, provenance=PROVENANCE))
    assert "dependencies" not in second
    assert props(second["metadata"])["projection_losses"][0]["record"] == relation


@pytest.mark.parametrize("locator", ["line:1", "line:999"])
def test_standard_edges_respect_explicit_endpoint_locators(tmp_path, locator):
    observed = inventory(tmp_path, "pip==26.0.1\nrequests==2.32.3\n")
    relation = {
        "parent": "pypi:pip@26.0.1",
        "child": "pypi:requests@2.32.3",
        "root": ".",
        "path": "requirements.txt",
        "locator": "evidence",
        "kind": "dependency",
        "parent_locator": locator,
        "child_locator": "line:2",
    }
    observed["semantic_dimensions"]["relationships"] = [relation]
    document = json.loads(export(observed, provenance=PROVENANCE))
    if locator == "line:1":
        assert len(document["dependencies"]) == 1
    else:
        assert "dependencies" not in document
        assert props(document["metadata"])["projection_losses"]


def test_conditional_edges_are_retained_as_evidence_and_not_promoted_to_active_standard_dependencies(tmp_path):
    observed = inventory(tmp_path, "pip==26.0.1\nrequests==2.32.3\n")
    relation = {
        "parent": "pypi:pip@26.0.1",
        "child": "pypi:requests@2.32.3",
        "root": ".",
        "path": "requirements.txt",
        "locator": "evidence",
        "kind": "dependency",
        "marker": 'python_version < "3.14"',
        "extras": ["test"],
        "activation": "unknown",
    }
    observed["semantic_dimensions"]["relationships"] = [relation]
    document = json.loads(export(observed, provenance=PROVENANCE))
    assert "dependencies" not in document
    assert props(document["metadata"])["inventory"]["semantic_dimensions"]["relationships"] == [relation]
    assert props(document["metadata"])["projection_losses"]


@pytest.mark.parametrize("field", ["code_sha256", "registry_sha256", "config_sha256", "producer", "environment_policy"])
def test_compatibility_identity_invalidates_on_each_semantic_provenance_change(tmp_path, field):
    observed = inventory(tmp_path)
    original = props(json.loads(export(observed, provenance=PROVENANCE))["metadata"])["compatibility_identity"]
    changed = {**PROVENANCE, field: "d" * 64 if field.endswith("_sha256") else "other-policy"}
    assert props(json.loads(export(observed, provenance=changed))["metadata"])["compatibility_identity"] != original


def test_exact_output_boundary_and_deadline_refuse_without_mutating_inventory(tmp_path):
    observed = inventory(tmp_path)
    original = deepcopy(observed)
    size = len(export(observed, provenance=PROVENANCE))
    assert len(export(observed, provenance=PROVENANCE, limit=size)) == size
    with pytest.raises(InputRefusal, match="output-budget"):
        export(observed, provenance=PROVENANCE, limit=size - 1)
    with pytest.raises(InputRefusal, match="deadline"):
        export(observed, provenance=PROVENANCE, deadline=time.monotonic() - 1)
    assert observed == original


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-sha",
        "outside-path",
        "unknown-root",
        "bad-package",
        "duplicate-occurrence",
        "failed-status",
        "wrong-version",
        "cyclic",
    ],
)
def test_unbound_or_unadmitted_inventory_is_refused(tmp_path, mutation):
    observed = inventory(tmp_path)
    dimensions = observed["semantic_dimensions"]
    record = dimensions["occurrences"][0]
    if mutation == "missing-sha":
        dimensions["inputs"][0]["sha256"] = None
    elif mutation == "outside-path":
        record["path"] = "../outside"
    elif mutation == "unknown-root":
        record["root"] = "unbound"
    elif mutation == "bad-package":
        record["package"] = "npm:invented@1"
    elif mutation == "duplicate-occurrence":
        dimensions["occurrences"].append(deepcopy(record))
    elif mutation == "failed-status":
        observed["inventory_status"] = "failed"
    elif mutation == "wrong-version":
        observed["schema_version"] = "future-incompatible"
    else:
        observed["loop"] = observed
    with pytest.raises((ValueError, InputRefusal)):
        export(observed, provenance=PROVENANCE)


@pytest.mark.parametrize(
    "mutation",
    [
        "bad-spec",
        "extra-key",
        "dangling-edge",
        "duplicate-ref",
        "duplicate-evidence-ref",
        "provides",
        "metadata-component",
        "nested-component",
        "services",
    ],
)
def test_schema_and_referential_integrity_reject_tampering(tmp_path, mutation):
    document = json.loads(export(inventory(tmp_path), provenance=PROVENANCE))
    ref = document["components"][0]["bom-ref"]
    if mutation == "bad-spec":
        document["specVersion"] = "9.9"
    elif mutation == "extra-key":
        document["components"][0]["invented"] = True
    elif mutation == "dangling-edge":
        document["dependencies"] = [{"ref": ref, "dependsOn": ["unknown"]}]
    elif mutation == "duplicate-ref":
        document["components"].append(deepcopy(document["components"][0]))
    elif mutation == "duplicate-evidence-ref":
        document["components"][0]["evidence"]["occurrences"][0]["bom-ref"] = ref
    elif mutation == "provides":
        document["dependencies"] = [{"ref": ref, "dependsOn": [], "provides": ["unknown"]}]
    elif mutation == "metadata-component":
        document["metadata"]["component"] = {"type": "library", "name": "duplicate", "bom-ref": ref}
    elif mutation == "nested-component":
        document["components"][0]["components"] = [{"type": "library", "name": "duplicate", "bom-ref": ref}]
    else:
        document["services"] = [{"name": "unexpected", "bom-ref": ref}]
    with pytest.raises((ValueError, ValidationError)):
        validate(document)


@pytest.mark.parametrize(
    "values",
    [
        [],
        [1],
        [True, 1],
        [False, 0],
        [1, 1],
        [None, None],
        [{"a": 1, "b": 2}, {"b": 2, "a": 1}],
        [[1, 2], [2, 1]],
        [[True], [1]],
        ["a", "a"],
        [{"x": [None, True]}, {"x": [None, 1]}],
    ],
)
def test_linear_uniqueness_matches_pinned_standard_validator_for_admitted_json_types(values):
    schema = {"type": "array", "uniqueItems": True}
    assert BoundedValidator(schema).is_valid(values) == Draft7Validator(schema).is_valid(values)


@pytest.mark.parametrize(
    "path,locator,expected",
    [
        ("scripts/python-build.in", "line:1", "305b162c8a85cf0d9ac4c6c7cf9890b4c8c25c80c591eefbdf4c35f48f64218c"),
        ("α/依存.txt", "field<>&", "53755db63e5478d5fb457d2456131b4b064c2e5ef35c1abec576c34180130309"),
        ("x\u2028y/req.txt", "field\u2029x", "5a2ebe5e6be801d3e70397d798827e906d847180c5516f289d437ee3604afbcd"),
        ("b/requirements.txt", 'x\\y"z', "d50b6d18a5d8d42e33e64af96124512420cfbad05873f2c4751ee4361eed3639"),
    ],
)
def test_occurrence_ids_match_independently_generated_go_json_vectors(tmp_path, path, locator, expected):
    # Vectors produced by Go1.27.1 stdlib Marshal+SHA256 with the reviewed
    # Syft adapter namespace, independently of this Python implementation.
    record = inventory(tmp_path)["semantic_dimensions"]["occurrences"][0]
    record.update(path=path, locator=locator)
    assert occurrence_identity(record) == "m046-" + expected


def test_wide_input_and_floats_are_refused_before_schema_work(tmp_path, monkeypatch):
    import evaluation.m046.cyclonedx_export as module

    with pytest.raises(ValueError, match="unsupported-inventory-value"):
        module.tree_bound({"number": 1.0}, time.monotonic() + 1)
    monkeypatch.setattr(module, "MAX_NODES", 4)
    with pytest.raises(InputRefusal, match="complexity"):
        module.tree_bound([1, 2, 3, 4, 5], time.monotonic() + 1)


def report_for(document):
    return {
        "matches": [
            {
                "vulnerability": {
                    "id": "GHSA-independent-case",
                    "severity": "High",
                    "fix": {"versions": ["26.2.0"], "state": "fixed"},
                },
                "artifact": {
                    "id": component["bom-ref"],
                    "name": component["name"],
                    "version": component["version"],
                    "purl": component["purl"],
                    "type": "python",
                    "locations": None,
                },
            }
            for component in document["components"]
        ]
    }


def test_matching_context_recovers_by_exact_id_without_purl_fanout_or_original_field_changes(tmp_path):
    inventory(tmp_path, "pip==26.0.1\n", "a/requirements.txt")
    inventory(tmp_path, 'pip==26.0.1; python_version < "3.15"\n', "b/requirements.txt")
    document = json.loads(export(scan(tmp_path), provenance=PROVENANCE))
    report = report_for(document)
    original = deepcopy(report)
    results = recover(document, report)
    assert len(results) == 2 and report == original
    assert {r["sourcebastion"]["occurrence"]["root"] for r in results} == {"a", "b"}
    assert {r["sourcebastion"]["activation"] for r in results} == {"unconditional", "unknown"}
    for before, after in zip(report["matches"], results):
        context = after.pop("sourcebastion")
        assert after == before and after["artifact"]["locations"] is None
        assert context["location_recovery"] == "exact-exported-occurrence-id"


def test_real_cvss_epss_decimals_survive_context_recovery(tmp_path):
    document = json.loads(export(inventory(tmp_path), provenance=PROVENANCE))
    report = report_for(document)
    report["matches"][0]["vulnerability"]["cvss"] = [
        {"version": "3.1", "metrics": {"baseScore": 7.5, "exploitabilityScore": 3.9}}
    ]
    report["matches"][0]["vulnerability"]["epss"] = [{"epss": 0.0031, "percentile": 0.42}]
    result = recover(document, report)
    assert result[0]["vulnerability"] == report["matches"][0]["vulnerability"]


@pytest.mark.parametrize("number", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_consumer_numbers_are_refused(tmp_path, number):
    document = json.loads(export(inventory(tmp_path), provenance=PROVENANCE))
    report = report_for(document)
    report["matches"][0]["vulnerability"]["score"] = number
    with pytest.raises(ValueError):
        recover(document, report)


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown-id",
        "wrong-purl",
        "wrong-version",
        "changed-occurrence",
        "changed-evidence",
        "duplicate-property",
        "changed-line",
        "changed-evidence-ref",
        "unbound-metadata-root",
    ],
)
def test_matching_mismatches_refuse_instead_of_guessing_context(tmp_path, mutation):
    document = json.loads(export(inventory(tmp_path), provenance=PROVENANCE))
    report = report_for(document)
    artifact = report["matches"][0]["artifact"]
    component = document["components"][0]
    if mutation == "unknown-id":
        artifact["id"] = "unknown"
    elif mutation == "wrong-purl":
        artifact["purl"] = "pkg:pypi/other@26.0.1"
    elif mutation == "wrong-version":
        artifact["version"] = "26.2.0"
    elif mutation == "changed-occurrence":
        prop = next(p for p in component["properties"] if p["name"] == PREFIX + "occurrence")
        value = json.loads(prop["value"])
        value["locator"] = "line:999"
        prop["value"] = json.dumps(value)
    elif mutation == "changed-evidence":
        component["evidence"]["occurrences"][0]["location"] = "another/file.txt"
    elif mutation == "duplicate-property":
        component["properties"].append(deepcopy(component["properties"][0]))
    elif mutation == "changed-line":
        component["evidence"]["occurrences"][0]["line"] = 999
    elif mutation == "changed-evidence-ref":
        component["evidence"]["occurrences"][0]["bom-ref"] = "another-unique-ref"
    else:
        prop = next(p for p in document["metadata"]["properties"] if p["name"] == PREFIX + "inventory")
        value = json.loads(prop["value"])
        value["semantic_dimensions"]["roots"] = ["unbound"]
        prop["value"] = json.dumps(value)
    with pytest.raises(ValueError):
        recover(document, report)


def test_recovered_output_is_precharged_at_exact_serialized_boundary(tmp_path, monkeypatch):
    import evaluation.m046.cyclonedx_matches as matching
    from evaluation.m046.static_cli import encode

    document = json.loads(export(inventory(tmp_path), provenance=PROVENANCE))
    report = report_for(document)
    report["matches"] *= 1
    report["matches"] = [deepcopy(report["matches"][0]) for _ in range(3)]
    original = deepcopy(report)
    results = recover(document, report)
    size = len(encode(results))
    monkeypatch.setattr(matching, "MAX_BYTES", size)
    assert len(encode(recover(document, report))) == size
    monkeypatch.setattr(matching, "MAX_BYTES", size - 1)
    with pytest.raises(InputRefusal, match="matching-context-output-budget"):
        recover(document, report)
    assert report == original
