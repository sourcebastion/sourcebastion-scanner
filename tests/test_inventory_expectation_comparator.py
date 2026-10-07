"""Comparator adverse cases use authored templates, never candidate output."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import runpy

import pytest

PROBE = runpy.run_path(str(Path(__file__).parents[1] / "scripts/verify-inventory-expectations.py"))
compare = PROBE["compare"]
CASES = json.loads((Path(__file__).parents[1] / PROBE["EXPECTATIONS"]).read_bytes())["cases"]


def observed(case):
    """Substitute opaque IDs in a synthetic authored record tree only."""
    actual = deepcopy(case["records"])
    actual.update(coverage=deepcopy(case["coverage"]), stages=deepcopy(case["stages"]))
    aliases = {
        row["id"]: "record:sha256:" + hashlib.sha256(row["id"].encode()).hexdigest()
        for rows in case["records"].values()
        for row in rows
    }
    for collection in PROBE["COLLECTIONS"]:
        actual[collection] = [PROBE["normalize"](row, aliases) for row in actual[collection]]
    actual["coverage"]["inputs"] = [PROBE["normalize"](row, aliases) for row in actual["coverage"]["inputs"]]
    return actual


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["case"])
def test_full_authored_template_accepts_opaque_ids_and_record_order(case):
    actual = observed(case)
    for collection in PROBE["COLLECTIONS"]:
        actual[collection].reverse()
    actual["coverage"]["inputs"].reverse()
    compare(case, actual)


@pytest.mark.parametrize(
    "field,value",
    [
        ("selected_version", "2.31.0"),
        ("directness", "transitive"),
        ("activation", "inactive"),
        ("scopes", ["runtime"]),
        ("groups", ["dev"]),
        ("marker", 'python_version < "3"'),
        ("extras", ["security"]),
        ("root_id", "unknown-root"),
        ("installed_environment_id", "unknown-env"),
        ("declared_range", ""),
        ("hashes", [{"algorithm": "sha256", "digest": "a" * 64, "kind": "artifact"}]),
    ],
)
def test_every_occurrence_field_stays_authoritative(field, value):
    case = next(case for case in CASES if case["case"] == "python-constraint-resolves")
    actual = observed(case)
    actual["occurrences"][0][field] = value
    with pytest.raises(ValueError):
        compare(case, actual)


@pytest.mark.parametrize(
    "field,value",
    [("path", "other.txt"), ("locator", "line:2"), ("source_sha256", "0" * 64), ("parser", "other-parser/1")],
)
def test_equal_package_identity_never_replaces_source_binding(field, value):
    actual = observed(CASES[0])
    actual["occurrences"][0]["source"][field] = value
    with pytest.raises(ValueError, match="expectation-unbound-source-anchor"):
        compare(CASES[0], actual)


@pytest.mark.parametrize("operation", ["drop", "duplicate", "unknown", "redirect"])
def test_selection_evidence_is_exact_and_duplicate_links_are_not_erased(operation):
    case = CASES[0]
    actual = observed(case)
    links = actual["occurrences"][0]["selection_declaration_ids"]
    if operation == "drop":
        links.pop()
    elif operation == "duplicate":
        links.append(links[0])
    elif operation == "unknown":
        links[0] = "unknown"
    else:
        links[0] = actual["analysis_scopes"][0]["id"]
    with pytest.raises(ValueError):
        compare(case, actual)


def test_input_reference_is_not_an_optional_dependency_edge():
    actual = observed(CASES[0])
    actual["input_references"] = []
    with pytest.raises(ValueError, match="expectation-record-count-mismatch"):
        compare(CASES[0], actual)


@pytest.mark.parametrize("target", ["record", "input", "coverage", "stage"])
def test_full_cardinalities_and_independent_stage_coverage_are_compared(target):
    actual = observed(CASES[0])
    if target == "record":
        actual["occurrences"].append(deepcopy(actual["occurrences"][0]))
    elif target == "input":
        actual["coverage"]["inputs"].append(deepcopy(actual["coverage"]["inputs"][0]))
    elif target == "coverage":
        actual["coverage"]["graph"] = "complete"
    else:
        actual["stages"]["matching"] = "succeeded"
    with pytest.raises(ValueError):
        compare(CASES[0], actual)


def test_ambiguous_source_anchor_refuses_instead_of_merging_records():
    case = deepcopy(CASES[0])
    duplicate = dict(case["records"]["occurrences"][0], id="occurrence:duplicate")
    case["records"]["occurrences"].append(duplicate)
    with pytest.raises(ValueError, match="expectation-ambiguous-source-anchor"):
        compare(case, observed(case))


def test_only_the_four_explicit_id_lists_ignore_order():
    case = deepcopy(CASES[0])
    case["records"]["occurrences"][0]["extras"] = ["one", "two"]
    actual = observed(case)
    actual["occurrences"][0]["selection_declaration_ids"].reverse()
    compare(case, actual)
    actual["occurrences"][0]["extras"].reverse()
    with pytest.raises(ValueError, match="expectation-record-fields-mismatch"):
        compare(case, actual)
