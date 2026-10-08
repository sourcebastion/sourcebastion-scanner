"""Comparator adverse cases use authored templates, never candidate output."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import runpy
import time

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


@pytest.mark.parametrize("name", ["symlink-escape", "symlink-cycle"])
def test_authored_symlink_fixture_is_bound_and_outside_sentinel_is_guarded(tmp_path, name):
    case = next(row for row in CASES if row["case"] == name)
    historical = {"files": {}, "symlinks": case["fixture_symlinks"]}
    root, identity, unchanged = PROBE["fixture_source"](case, historical, tmp_path)
    assert root == tmp_path / "source" and len(identity) == 64
    time.sleep(1.1)
    unchanged()
    unchanged()
    (tmp_path / "outside.txt").write_bytes(b"changed")
    with pytest.raises(AssertionError):
        unchanged()


@pytest.mark.parametrize(
    "name",
    [
        "python-include-cycle",
        "python-include-escape",
        "symlink-cycle",
        "symlink-escape",
        "python-malformed",
        "python-poetry",
        "python-constraint-only",
    ],
)
def test_negative_fixture_cannot_be_promoted_to_complete_inventory(name):
    case = next(row for row in CASES if row["case"] == name)
    actual = observed(case)
    actual["stages"]["inventory"] = "complete"
    with pytest.raises(ValueError, match="expectation-stages-mismatch"):
        compare(case, actual)


def test_refused_escape_cannot_acquire_outside_target_authority():
    case = next(row for row in CASES if row["case"] == "python-include-escape")
    actual = observed(case)
    actual["input_references"][0]["target_path"] = "outside.txt"
    with pytest.raises(ValueError, match="expectation-record-fields-mismatch"):
        compare(case, actual)


@pytest.mark.parametrize("name", ["python-constraint-only", "a", "a" * 80])
def test_proof_failure_reports_bounded_reviewed_fixture_identity(name):
    assert PROBE["fixture_case_id"](name) == name
    assert PROBE["failure_record"](ValueError("private-repository-token"), name) == {
        "status": "native-source-expectations-failed", "reason": "ValueError", "case": name,
    }


@pytest.mark.parametrize("name", [None, True, 1, "", "A", "-a", "a" * 81, "a/b", "a\\b", "a\n", "\u00e9", "a\u2028b"])
def test_proof_failure_omits_invalid_or_unavailable_fixture_identity(name):
    with pytest.raises(ValueError, match="invalid-fixture-case-id"):
        PROBE["fixture_case_id"](name)
    assert PROBE["failure_record"](RuntimeError("private-repository-token"), name) == {
        "status": "native-source-expectations-failed", "reason": "RuntimeError",
    }


@pytest.mark.parametrize("case", [{}, {"case": "private/path"}, {"case": None}, None, []])
def test_malformed_fixture_cannot_report_the_previous_case(case):
    progress = {}
    assert PROBE["begin_fixture"]({"case": "python-constraint-only"}, progress) == "python-constraint-only"
    with pytest.raises((KeyError, TypeError, ValueError)) as caught:
        PROBE["begin_fixture"](case, progress)
    assert "case" not in progress
    assert "case" not in PROBE["failure_record"](caught.value, progress.get("case"))


def test_fixture_identity_rejects_str_subclasses():
    class PrivateCase(str):
        pass

    with pytest.raises(ValueError, match="invalid-fixture-case-id"):
        PROBE["fixture_case_id"](PrivateCase("python-constraint-only"))


def test_global_guards_cannot_attribute_failure_to_the_last_fixture():
    import ast

    tree = ast.parse((Path(__file__).parents[1] / "scripts/verify-inventory-expectations.py").read_text())
    verify = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "verify")
    loop_index = next(index for index, node in enumerate(verify.body) if isinstance(node, ast.For))
    final_guard = verify.body[loop_index + 2]
    assert isinstance(final_guard, ast.Assert) and "modules(installed)" in ast.unparse(final_guard)
    clear = ast.Module(body=[verify.body[loop_index + 1]], type_ignores=[])
    namespace = {"progress": {"case": "python-constraint-only"}}
    exec(compile(clear, "<proof-global-case-reset>", "exec"), namespace)
    assert namespace["progress"] == {}
    assert "case" not in PROBE["failure_record"](AssertionError(), namespace["progress"].get("case"))


@pytest.mark.parametrize("name", ["python-poetry-graph", "python-pdm-graph"])
@pytest.mark.parametrize("collection", ["relationships", "dependency_selectors"])
@pytest.mark.parametrize("damage", ["duplicate-parent", "unknown-parent", "same-package-other-group"])
def test_grouped_lock_edges_require_the_unique_source_bound_parent(name, collection, damage):
    case = next(case for case in CASES if case["case"] == name)
    actual = observed(case)
    first, second = actual[collection][:2]
    assert first["source"] == second["source"]
    if damage == "unknown-parent":
        second["parent_id"] = "private-path-must-not-bind"
    elif damage == "duplicate-parent":
        second["parent_id"] = first["parent_id"]
    else:
        first["parent_id"], second["parent_id"] = second["parent_id"], first["parent_id"]
    with pytest.raises(ValueError):
        compare(case, actual)


@pytest.mark.parametrize("name", ["python-poetry-graph", "python-pdm-graph", "python-uv-graph", "python-pylock-complete"])
@pytest.mark.parametrize("collection", ["relationships", "dependency_selectors", "applicability"])
def test_lock_graph_missing_evidence_cannot_pass(name, collection):
    case = next(case for case in CASES if case["case"] == name)
    actual = observed(case)
    if not actual[collection]:
        assert name == "python-pylock-complete" and collection == "applicability"
        return
    actual[collection].pop()
    with pytest.raises(ValueError, match="expectation-record-count-mismatch"):
        compare(case, actual)
