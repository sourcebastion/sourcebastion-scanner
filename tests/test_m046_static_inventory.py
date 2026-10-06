"""Independent rich pip oracle plus resolver and refusal boundary cases."""

import json
from pathlib import PurePosixPath

import pytest

from evaluation.m046.corpus import CORPUS
from evaluation.m046.run import compare, materialize, snapshot
from evaluation.m046.static_inputs import Limits, Source
from evaluation.m046.static_inventory import evaluate

PIP_CASES = [
    fixture
    for fixture in CORPUS
    if fixture["ecosystem"] == "python"
    and fixture["files"]
    and all(PurePosixPath(path).suffix in {".in", ".txt", ".pip"} for path in fixture["files"])
    and not fixture["symlinks"]
]


@pytest.mark.parametrize("fixture", PIP_CASES, ids=lambda fixture: fixture["id"])
def test_supported_pip_inputs_match_the_independent_full_contract(tmp_path, fixture):
    root = tmp_path / "source"
    materialize(fixture, root)
    original = snapshot(root)
    with Source(root) as source:
        observed = evaluate(source)
    differences = compare(fixture["expected"], observed)
    assert differences["full_contract_agreement"], json.dumps(differences, indent=2)
    assert snapshot(root) == original
    assert observed["matching_status"] == "not-run" and observed["sbom_status"] == "not-run"


def write(root, name, content):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def scan(root, *, mapping=None, limits=None):
    with Source(root, limits) as source:
        return evaluate(source, mapping=mapping)


def test_repeated_include_is_deduplicated_without_losing_distinct_roots(tmp_path):
    write(tmp_path, "a/requirements.txt", "-r ../shared/base.config\n-r ../shared/base.config\n")
    write(tmp_path, "b/requirements.txt", "-r ../shared/base.config\n")
    write(tmp_path, "shared/base.config", "requests==2.32.3\n")
    observed = scan(tmp_path)
    assert observed["packages"] == ["pypi:requests@2.32.3"]
    occurrences = observed["semantic_dimensions"]["occurrences"]
    assert [(r["path"], r["root"]) for r in occurrences] == [("shared/base.config", "a"), ("shared/base.config", "b")]
    assert observed["edges"] == []


def test_constraints_cannot_become_independent_packages(tmp_path):
    write(tmp_path, "constraints.txt", "requests==2.32.3\n")
    observed = scan(tmp_path)
    assert observed["packages"] == [] and observed["inventory_status"] == "complete"
    declarations = observed["semantic_dimensions"]["declaration_records"]
    assert len(declarations) == 1 and declarations[0]["scope"] == "constraint"


def test_constraint_includes_stay_in_constraint_role(tmp_path):
    write(tmp_path, "requirements.txt", "requests>=2\n-c constraints.txt\n")
    write(tmp_path, "constraints.txt", "-r shared/deps.config\n")
    write(tmp_path, "shared/deps.config", "requests==2.32.3\nurllib3==2.2.2\n")
    observed = scan(tmp_path)
    assert observed["packages"] == ["pypi:requests@2.32.3"]
    assert len(observed["semantic_dimensions"]["occurrences"]) == 1
    assert len([r for r in observed["semantic_dimensions"]["declaration_records"] if r["scope"] == "constraint"]) == 2


def test_conditional_constraint_is_explicitly_unresolved(tmp_path):
    write(tmp_path, "requirements.txt", "requests>=2\n-c constraints.txt\n")
    write(tmp_path, "constraints.txt", 'requests==2.32.3; python_version < "3.12"\n')
    observed = scan(tmp_path)
    assert observed["packages"] == [] and observed["inventory_status"] == "partial"
    assert "conditional-constraint-unresolved" in observed["refusal_codes"]


def test_incompatible_same_root_pins_are_not_two_installed_versions(tmp_path):
    write(tmp_path, "requirements.txt", "requests==1\nrequests==2\n")
    observed = scan(tmp_path)
    assert observed["packages"] == [] and observed["inventory_status"] == "partial"
    assert "conflicting-root-declarations" in observed["refusal_codes"]


def test_explicit_mapping_is_data_and_does_not_grant_network_or_execution(tmp_path):
    write(tmp_path, "custom.config", "requests==2.32.3\n")
    assert scan(tmp_path)["packages"] == []
    assert scan(tmp_path, mapping={"custom.config": "pip-requirements"})["packages"] == ["pypi:requests@2.32.3"]
    for mapping in ({"custom.config": "execute-setup"}, {"../outside": "pip-requirements"}):
        with pytest.raises(ValueError):
            scan(tmp_path, mapping=mapping)


def test_other_known_formats_are_visible_without_guessing_packages(tmp_path):
    write(tmp_path, "pyproject.toml", '[project]\ndependencies=["requests==2.32.3"]\n')
    observed = scan(tmp_path)
    assert observed["packages"] == [] and observed["inventory_status"] == "partial"
    (record,) = observed["semantic_dimensions"]["inputs"]
    assert record["format"] == "pep621" and record["disposition"] == "unsupported"


def test_include_symlink_never_consumes_outside_content(tmp_path):
    root = tmp_path / "source"
    write(root, "requirements.txt", "-r alias.pip\n")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside==99\n")
    (root / "alias.pip").symlink_to(outside)
    observed = scan(root)
    assert observed["packages"] == [] and observed["inventory_status"] == "partial"
    assert "non-regular-input" in observed["refusal_codes"]


def test_discovery_overflow_is_not_successful_empty_inventory(tmp_path):
    write(tmp_path, "a.txt", "requests==1\n")
    write(tmp_path, "b.txt", "requests==2\n")
    observed = scan(tmp_path, limits=Limits(entries=1))
    assert observed["inventory_status"] == "partial" and observed["packages"] == []
    assert observed["semantic_dimensions"]["fidelity"]["discovery"] == "partial"
    assert "input-traversal-budget-exceeded" in observed["refusal_codes"]


def test_expired_source_returns_explicit_failed_axes(tmp_path):
    write(tmp_path, "requirements.txt", "requests==1\n")
    with Source(tmp_path) as source:
        source.deadline = 0
        observed = evaluate(source)
    assert observed["inventory_status"] == "failed" and observed["packages"] == []
    assert observed["refusal_codes"] == ["input-deadline-exceeded"]


def test_include_depth_boundary_is_explicit(tmp_path, monkeypatch):
    from evaluation.m046 import static_inventory

    monkeypatch.setattr(static_inventory, "MAX_INCLUDE_DEPTH", 2)
    write(tmp_path, "requirements.txt", "-r a.pip\n")
    write(tmp_path, "a.pip", "-r b.pip\n")
    write(tmp_path, "b.pip", "requests==1\n")
    assert scan(tmp_path)["packages"] == ["pypi:requests@1"]
    write(tmp_path, "b.pip", "-r c.pip\n")
    write(tmp_path, "c.pip", "requests==1\n")
    overflow = scan(tmp_path)
    assert overflow["packages"] == [] and "include-depth-budget-exceeded" in overflow["refusal_codes"]


def test_include_target_boundary_is_explicit(tmp_path, monkeypatch):
    from evaluation.m046 import static_inventory

    monkeypatch.setattr(static_inventory, "MAX_INCLUDE_TARGETS", 2)
    write(tmp_path, "requirements.txt", "-r a.pip\n-r b.pip\n")
    write(tmp_path, "a.pip", "requests==1\n")
    write(tmp_path, "b.pip", "pytest==8\n")
    assert len(scan(tmp_path)["packages"]) == 2
    write(tmp_path, "requirements.txt", "-r a.pip\n-r b.pip\n-r c.pip\n")
    write(tmp_path, "c.pip", "urllib3==2\n")
    overflow = scan(tmp_path)
    assert overflow["packages"] == [] and "include-target-budget-exceeded" in overflow["refusal_codes"]


@pytest.mark.parametrize("constraint", ["foo==1.0.0", "foo==1.0+abc"])
def test_equivalent_and_local_versions_use_pep440_intersection(tmp_path, constraint):
    write(tmp_path, "requirements.txt", "foo==1.0\n-c constraints.txt\n")
    write(tmp_path, "constraints.txt", constraint + "\n")
    observed = scan(tmp_path)
    expected = "1.0+abc" if "+abc" in constraint else "1.0"
    assert observed["packages"] == ["pypi:foo@" + expected]
    assert observed["inventory_status"] == "complete"


def test_sibling_range_can_refuse_an_incompatible_pin(tmp_path):
    write(tmp_path, "requirements.txt", "foo==1\nfoo>=2\n")
    observed = scan(tmp_path)
    assert observed["packages"] == [] and observed["inventory_status"] == "partial"
    assert "conflicting-root-declarations" in observed["refusal_codes"]


def test_extras_are_not_valid_constraints(tmp_path):
    write(tmp_path, "requirements.txt", "foo>=1\n-c constraints.txt\n")
    write(tmp_path, "constraints.txt", "foo[extra]==1\n")
    observed = scan(tmp_path)
    assert observed["packages"] == [] and "invalid-constraint-extras" in observed["refusal_codes"]


def test_refused_parent_does_not_promote_child_to_independent_root(tmp_path):
    write(tmp_path, "requirements.txt", "-r child.pip\n--unknown-option\n")
    write(tmp_path, "child.pip", "foo==1\n")
    observed = scan(tmp_path)
    assert observed["packages"] == [] and observed["inventory_status"] == "partial"


def test_literal_quotes_in_include_filename_are_not_stripped_twice(tmp_path):
    write(tmp_path, "requirements.txt", "-r \"'base.txt'\"\n")
    write(tmp_path, "'base.txt'", "foo==1\n")
    write(tmp_path, "base.txt", "bar==2\n")
    observed = scan(tmp_path)
    occurrence = next(
        record for record in observed["semantic_dimensions"]["occurrences"] if record["package"] == "pypi:foo@1"
    )
    assert occurrence["path"] == "'base.txt'"
    assert any(reference["target"] == "'base.txt'" for reference in observed["semantic_dimensions"]["references"])


def test_quoted_whitespace_in_filename_remains_literal(tmp_path):
    write(tmp_path, "requirements.txt", '-r " base.txt "\n')
    write(tmp_path, " base.txt ", "good==1\n")
    write(tmp_path, "base.txt", "wrong==2\n")
    observed = scan(tmp_path)
    assert "pypi:good@1" in observed["packages"]
    assert observed["inventory_status"] == "complete"
    occurrence = next(
        record for record in observed["semantic_dimensions"]["occurrences"] if record["package"] == "pypi:good@1"
    )
    assert occurrence["path"] == " base.txt "
    assert any(reference["target"] == " base.txt " for reference in observed["semantic_dimensions"]["references"])


def test_changed_input_after_parsing_refuses_all_selections(tmp_path, monkeypatch):
    from evaluation.m046 import static_inventory

    write(tmp_path, "requirements.txt", "foo==1\n")
    original = static_inventory.parse

    def mutate_after_parse(*args, **kwargs):
        document = original(*args, **kwargs)
        write(tmp_path, "requirements.txt", "foo==2\n")
        return document

    monkeypatch.setattr(static_inventory, "parse", mutate_after_parse)
    observed = scan(tmp_path)
    assert observed["inventory_status"] == "failed" and observed["packages"] == []
    assert observed["refusal_codes"] == ["changed-input-path"]


def test_shared_constraints_cannot_expand_output_past_dimension_budget(tmp_path, monkeypatch):
    from evaluation.m046 import static_inventory

    monkeypatch.setattr(static_inventory, "MAX_OCCURRENCES", 32)
    for index in range(5):
        write(tmp_path, f"root{index}/requirements.txt", "foo==1\n-c ../shared/constraints.config\n")
    write(tmp_path, "shared/constraints.config", "".join(f"bar{index}==1\n" for index in range(8)))
    observed = scan(tmp_path)
    assert observed["inventory_status"] == "failed" and observed["packages"] == []
    assert observed["refusal_codes"] == ["semantic-expansion-budget-exceeded"]


def test_resolution_work_overflow_is_explicit(tmp_path, monkeypatch):
    from evaluation.m046 import static_inventory

    monkeypatch.setattr(static_inventory, "MAX_RESOLUTION_STEPS", 2)
    write(tmp_path, "requirements.txt", "foo==1\n")
    observed = scan(tmp_path)
    assert observed["inventory_status"] == "failed" and observed["packages"] == []
    assert observed["refusal_codes"] == ["resolution-step-budget-exceeded"]


@pytest.mark.parametrize("content", ['foo>=1; python_version < "3.12"\n', 'foo==1; python_version < "3.12"\n'])
def test_conditional_declarations_do_not_claim_unconditional_environment(tmp_path, content):
    write(tmp_path, "constraints.txt", content)
    observed = scan(tmp_path)
    assert observed["packages"] == []
    assert observed["semantic_dimensions"]["fidelity"]["environment"] == "conditional-unknown"


def test_reordered_equivalent_marker_contexts_cannot_hide_pin_conflict(tmp_path):
    write(
        tmp_path,
        "requirements.txt",
        'foo==1; os_name == "posix" and python_version < "3.12"\nfoo==2; python_version < "3.12" and os_name == "posix"\n',
    )
    observed = scan(tmp_path)
    assert observed["packages"] == [] and observed["inventory_status"] == "partial"
    assert "conflicting-root-declarations" in observed["refusal_codes"]


def test_unproved_overlapping_marker_contexts_are_explicit(tmp_path):
    write(tmp_path, "requirements.txt", 'foo==1; os_name == "posix"\nfoo==2; python_version < "3.12"\n')
    observed = scan(tmp_path)
    assert observed["packages"] == [] and observed["inventory_status"] == "partial"
    assert "overlapping-marker-context-unresolved" in observed["refusal_codes"]


def test_marker_compatibility_checks_all_declarations_in_each_context(tmp_path):
    write(
        tmp_path,
        "requirements.txt",
        'foo>=1; os_name == "posix"\nfoo==1; os_name == "posix"\nfoo>=1; platform_system == "Linux"\nfoo==2; platform_system == "Linux"\n',
    )
    observed = scan(tmp_path)
    assert observed["packages"] == [] and observed["inventory_status"] == "partial"
    assert "overlapping-marker-context-unresolved" in observed["refusal_codes"]


def test_unsupported_known_manifest_has_unknown_environment(tmp_path):
    write(tmp_path, "pyproject.toml", "[project]\ndependencies=[\"foo==1; os_name == 'posix'\"]\n")
    observed = scan(tmp_path)
    assert observed["semantic_dimensions"]["fidelity"]["environment"] == "unknown"


def test_new_nested_input_after_discovery_refuses_complete_inventory(tmp_path, monkeypatch):
    write(tmp_path, "project/requirements.txt", "foo==1\n")
    original = Source.discover

    def mutate_after_discovery(source):
        yield from original(source)
        write(tmp_path, "project/new.pip", "missed==2\n")

    monkeypatch.setattr(Source, "discover", mutate_after_discovery)
    observed = scan(tmp_path)
    assert observed["inventory_status"] == "failed" and observed["packages"] == []
    assert observed["refusal_codes"] == ["changed-input-directory"]
