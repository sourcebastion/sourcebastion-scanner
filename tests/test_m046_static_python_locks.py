"""Pinned Python lock schemas, conditional groups and source-aware graph proof."""

import hashlib

import pytest

from evaluation.m046.static_inputs import Source
from evaluation.m046.static_inventory import evaluate
from evaluation.m046.static_locks import parse
from evaluation.m046.corpus import CORPUS
from evaluation.m046.run import compare, materialize

SHA = "a" * 64
POETRY = '[metadata]\nlock-version="2.1"\npython-versions=">=3.12"\ncontent-hash="' + SHA + '"\n'
PDM = (
    '[metadata]\nlock_version="4.5.0"\ngroups=["default","test"]\nstrategy=["inherit_metadata"]\ncontent_hash="sha256:'
    + SHA
    + '"\n'
)
UV = 'version=1\nrevision=3\nrequires-python=">=3.12"\n'
SOURCE = 'source={registry="https://pypi.org/simple"}\n'


@pytest.mark.parametrize(
    "fixture_id",
    ["python-poetry", "python-poetry-graph", "python-pdm", "python-pdm-graph", "python-uv", "python-uv-graph"],
)
def test_pinned_python_lock_matches_independent_rich_oracle(tmp_path, fixture_id):
    fixture = next(item for item in CORPUS if item["id"] == fixture_id)
    materialize(fixture, tmp_path / "source")
    with Source(tmp_path / "source") as source:
        observed = evaluate(source)
    differences = compare(fixture["expected"], observed)
    assert differences["full_contract_agreement"], differences


def artifact(name, version="1", style="poetry"):
    if style == "uv":
        return (
            'wheels=[{url="https://packages.invalid/'
            + name
            + "-"
            + version
            + '-py3-none-any.whl",hash="sha256:'
            + SHA
            + '"}]\n'
        )
    return 'files=[{file="' + name + "-" + version + '-py3-none-any.whl",hash="sha256:' + SHA + '"}]\n'


def package(name="foo", version="1", style="poetry", extra=""):
    header = '[[package]]\nname="' + name + '"\nversion="' + version + '"\n'
    fields = {
        "poetry": 'optional=false\npython-versions=">=3.12"\ngroups=["main"]\n',
        "pdm": 'requires_python=">=3.12"\ngroups=["default"]\n',
        "uv": SOURCE,
    }
    return header + fields[style] + artifact(name, version, style) + extra


def run(tmp_path, content, style):
    (tmp_path / {"poetry": "poetry.lock", "pdm": "pdm.lock", "uv": "uv.lock"}[style]).write_text(content)
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    with Source(tmp_path) as source:
        observed = evaluate(source)
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    return observed


@pytest.mark.parametrize("style,header", [("poetry", POETRY), ("pdm", PDM), ("uv", UV)])
def test_pinned_registry_subset_preserves_occurrence_but_not_activation(tmp_path, style, header):
    observed = run(tmp_path, header + package(style=style), style)
    assert observed["inventory_status"] == "complete"
    assert observed["packages"] == ["pypi:foo@1"]
    (occurrence,) = observed["semantic_dimensions"]["occurrences"]
    assert occurrence["activation"] == "unknown" and occurrence["hashes"] == ["sha256:" + SHA]
    assert occurrence["source_kind"] == ("registry-asserted" if style == "uv" else "unknown")
    assert occurrence["source_identity"] == (
        hashlib.sha256(b"https://pypi.org/simple").hexdigest() if style == "uv" else None
    )
    assert observed["sbom_status"] == observed["matching_status"] == "not-run"


def test_poetry_group_markers_and_optional_metadata_are_separate(tmp_path):
    content = (
        package(extra="markers={Main=\"os_name == 'posix'\"}\n")
        .replace('groups=["main"]', 'groups=["Main","test"]')
        .replace("optional=false", "optional=true")
    )
    observed = run(tmp_path, POETRY + content, "poetry")
    first, second = observed["semantic_dimensions"]["occurrences"]
    assert first["scope"] == "group:main" and first["marker"] == 'os_name == "posix"'
    assert second["scope"] == "group:test" and second["marker"] is None
    assert first["optional"] is second["optional"] is True
    assert first["locator"] != second["locator"]
    assert all(row["activation"] == "unknown" for row in (first, second))


def test_pdm_multigroup_occurrences_and_dependency_ranges_preserve_child_entry(tmp_path):
    root = package("parent", style="pdm", extra='dependencies=["foo>=1,<2"]\n').replace(
        'groups=["default"]', 'groups=["default","test"]'
    )
    child = package(style="pdm").replace('groups=["default"]', 'groups=["default","test"]')
    observed = run(tmp_path, PDM + root + child, "pdm")
    assert observed["inventory_status"] == "complete"
    assert len(observed["semantic_dimensions"]["occurrences"]) == 4
    edges = observed["semantic_dimensions"]["relationships"]
    assert len(edges) == 2 and {edge["scope"] for edge in edges} == {"group:default", "group:test"}
    assert all(edge["child_locator"] == "package[1]" and edge["activation"] == "unknown" for edge in edges)
    assert all(edge["declared_constraint"] == ">=1,<2" for edge in edges)


def test_poetry_constraint_selects_one_version_without_guessing_multiple_variants(tmp_path):
    root = package("parent", extra='[package.dependencies]\nfoo=">=2,<3"\n')
    child1 = package("foo", "1", extra="markers=\"python_version < '3.14'\"\n")
    child2 = package("foo", "2", extra="markers=\"python_version >= '3.14'\"\n")
    observed = run(tmp_path, POETRY + root + child1 + child2, "poetry")
    assert observed["inventory_status"] == "complete" and observed["edges"] == [("pypi:parent@1", "pypi:foo@2")]
    (edge,) = observed["semantic_dimensions"]["relationships"]
    assert edge["child_locator"] == "package[2]" and edge["constraint_dialect"] == "poetry-core-2.1.3"


def test_uv_marker_is_retained_as_simplified_root_context_evidence(tmp_path):
    root = package(
        "parent", style="uv", extra='dependencies=[{name="foo",marker="python_version < \'3.14\'",extra=["test"]}]\n'
    )
    observed = run(tmp_path, UV + root + package(style="uv"), "uv")
    (edge,) = observed["semantic_dimensions"]["relationships"]
    assert edge["marker"] == 'python_version < "3.14"' and edge["extras"] == ["test"]
    assert edge["marker_semantics"] == "simplified-relative-to-root-python" and edge["activation"] == "unknown"
    assert observed["semantic_dimensions"]["environment_records"][0]["requires_python"] == ">=3.12"


@pytest.mark.parametrize("selector", ['name="foo"', 'name="foo",version="1"'])
def test_uv_omitted_source_is_not_repaired_by_an_ambiguous_name(tmp_path, selector):
    root = package("parent", style="uv", extra="dependencies=[{" + selector + "}]\n")
    child = package(style="uv")
    other = package(style="uv").replace("https://pypi.org/simple", "https://other.invalid/simple")
    observed = run(tmp_path, UV + root + child + other, "uv")
    assert observed["inventory_status"] == "partial" and observed["edges"] == []


def test_pdm_extra_variants_are_not_deduplicated_to_one_purl(tmp_path):
    root = package("parent", style="pdm", extra='dependencies=["foo[test]>=1"]\n')
    child = package(style="pdm")
    extra_child = package(style="pdm", extra='extras=["test"]\n')
    observed = run(tmp_path, PDM + root + child + extra_child, "pdm")
    assert observed["inventory_status"] == "complete"
    (edge,) = observed["semantic_dimensions"]["relationships"]
    assert edge["child_locator"] == "package[2]" and edge["extras"] == ["test"]
    assert len(observed["semantic_dimensions"]["occurrences"]) == 3


def test_uv_equal_purls_keep_exact_registry_identity_and_informational_edge(tmp_path):
    root = package(
        "parent",
        style="uv",
        extra='dependencies=[{name="foo",version="1",source={registry="https://other.invalid/simple"}}]\n',
    )
    first = package(style="uv")
    second = package(style="uv").replace("https://pypi.org/simple", "https://other.invalid/simple")
    observed = run(tmp_path, UV + root + first + second, "uv")
    assert observed["inventory_status"] == "partial" and "overlapping-lock-variants" in observed["refusal_codes"]
    (edge,) = observed["semantic_dimensions"]["relationships"]
    assert edge["child_locator"] == "package[2]"
    assert edge["child_source_identity"] == hashlib.sha256(b"https://other.invalid/simple").hexdigest()
    assert edge["activation"] == "unknown"
    assert "other.invalid" not in repr(observed)


@pytest.mark.parametrize("selected,accepted", [("1+local", False), ("1.0", True), ("2", False)])
def test_uv_exact_package_version_is_not_a_pep440_public_pin(tmp_path, selected, accepted):
    parent = package(
        "parent",
        style="uv",
        extra='dependencies=[{name="foo",version="1",source={registry="https://pypi.org/simple"}}]\n',
    )
    observed = run(tmp_path, UV + parent + package("foo", selected, style="uv"), "uv")
    assert bool(observed["edges"]) is accepted
    assert observed["inventory_status"] == ("complete" if accepted else "partial")
    if accepted:
        assert observed["semantic_dimensions"]["relationships"][0]["exact_version"] == "1"
    else:
        assert "missing-lock-dependency" in observed["refusal_codes"]


@pytest.mark.parametrize(
    "selector", ['name="foo",version="1"', 'name="foo",source={registry="https://pypi.org/simple"}']
)
def test_uv_independent_omitted_identity_fields_require_global_unique_name(tmp_path, selector):
    parent = package("parent", style="uv", extra="dependencies=[{" + selector + "}]\n")
    observed = run(tmp_path, UV + parent + package(style="uv"), "uv")
    assert observed["inventory_status"] == "complete" and observed["edges"] == [("pypi:parent@1", "pypi:foo@1")]


def test_uv_version_filter_does_not_repair_an_omitted_source_for_ambiguous_name(tmp_path):
    parent = package("parent", style="uv", extra='dependencies=[{name="foo",version="1"}]\n')
    observed = run(tmp_path, UV + parent + package("foo", "1", style="uv") + package("foo", "2", style="uv"), "uv")
    assert observed["inventory_status"] == "partial" and observed["edges"] == []
    assert "ambiguous-lock-dependency" in observed["refusal_codes"]


def test_uv_public_lock_version_allows_an_asserted_local_wheel_version(tmp_path):
    content = UV + package(style="uv").replace("foo-1-py3-none-any.whl", "foo-1+local-py3-none-any.whl")
    observed = run(tmp_path, content, "uv")
    assert observed["inventory_status"] == "complete" and observed["packages"] == ["pypi:foo@1"]
    assert observed["semantic_dimensions"]["occurrences"][0]["activation"] == "unknown"


def test_uv_sdist_filename_is_not_a_package_identity_assertion(tmp_path):
    content = (
        UV
        + '[[package]]\nname="foo"\nversion="1"\n'
        + SOURCE
        + 'sdist={url="https://packages.invalid/source.zip",hash="sha256:'
        + SHA
        + '"}\n'
    )
    observed = run(tmp_path, content, "uv")
    assert observed["inventory_status"] == "complete" and observed["packages"] == ["pypi:foo@1"]
    assert observed["semantic_dimensions"]["occurrences"][0]["hashes"] == ["sha256:" + SHA]


@pytest.mark.parametrize(
    "second",
    [
        '{name="foo-bar",extra=["z","a"]}',
        '{name="Foo_Bar",version="1.0",source={registry="https://pypi.org/simple"},extra=["a","z"]}',
    ],
)
def test_uv_duplicate_dependencies_are_refused_after_resolving_identity(tmp_path, second):
    parent = package("parent", style="uv", extra='dependencies=[{name="Foo_Bar",extra=["a","z"]},' + second + "]\n")
    observed = run(tmp_path, UV + parent + package("foo_bar", style="uv"), "uv")
    assert observed["inventory_status"] == "partial" and observed["edges"] == []
    assert "duplicate-lock-dependency" in observed["refusal_codes"]
    assert observed["semantic_dimensions"]["inputs"][0]["disposition"] == "malformed"


def test_uv_repeated_target_with_unproved_marker_context_remains_partial(tmp_path):
    parent = package(
        "parent", style="uv", extra='dependencies=[{name="foo"},{name="foo",marker="python_version >= \'3.12\'"}]\n'
    )
    observed = run(tmp_path, UV + parent + package(style="uv"), "uv")
    assert observed["inventory_status"] == "partial" and observed["edges"] == []
    assert "repeated-lock-dependency-context" in observed["refusal_codes"]


def test_pdm_requested_extra_set_order_does_not_change_candidate_identity(tmp_path):
    root = package("parent", style="pdm", extra='dependencies=["foo[a,z]>=1"]\n')
    child = package(style="pdm", extra='extras=["z","a"]\n')
    observed = run(tmp_path, PDM + root + child, "pdm")
    assert observed["inventory_status"] == "complete"
    (edge,) = observed["semantic_dimensions"]["relationships"]
    assert edge["child_locator"] == "package[1]" and edge["extras"] == ["a", "z"]


@pytest.mark.parametrize("constraint", ["1", "1.*"])
def test_poetry_bare_version_and_wildcard_constraints_are_not_package_names(tmp_path, constraint):
    parent = package("parent", extra='[package.dependencies]\nfoo="' + constraint + '"\n')
    observed = run(tmp_path, POETRY + parent + package(), "poetry")
    assert observed["inventory_status"] == "complete" and observed["edges"] == [("pypi:parent@1", "pypi:foo@1")]
    assert observed["semantic_dimensions"]["relationships"][0]["declared_constraint"] == constraint


def test_group_dependency_expansion_is_bounded_before_retention(tmp_path, monkeypatch):
    from evaluation.m046 import static_python_lock_records

    monkeypatch.setattr(static_python_lock_records, "MAX_RECORDS", 2)
    root = package("parent", style="pdm", extra='dependencies=["foo>=1"]\n').replace(
        'groups=["default"]', 'groups=["default","test","build"]'
    )
    content = (
        PDM.replace('groups=["default","test"]', 'groups=["default","test","build"]') + root + package(style="pdm")
    )
    (tmp_path / "pdm.lock").write_text(content)
    with Source(tmp_path) as source:
        observed = evaluate(source)
    assert observed["inventory_status"] == "failed"
    assert observed["packages"] == observed["edges"] == []
    assert observed["refusal_codes"] == ["lock-edge-budget-exceeded"]


@pytest.mark.parametrize("constraint", ["^1.2", "~1.2", "1.* || 2.*"])
def test_poetry_maintained_constraint_dialect_matches_one_lock_entry(tmp_path, constraint):
    content = (
        POETRY + package("parent", extra='[package.dependencies]\nfoo="' + constraint + '"\n') + package("foo", "1.2.5")
    )
    observed = run(tmp_path, content, "poetry")
    assert observed["inventory_status"] == "complete" and observed["edges"] == [("pypi:parent@1", "pypi:foo@1.2.5")]
    assert observed["semantic_dimensions"]["relationships"][0]["declared_constraint"] == constraint


@pytest.mark.parametrize(
    "raw,version,accepted",
    [
        ("^0.2.3", "0.2.4", True),
        ("^0.2.3", "0.3", False),
        ("~1.2", "1.9", False),
        ("~=1.2", "1.9", True),
        ("^1.2", "1.2.5.post1", True),
        ("1.* || 2.*", "2", True),
    ],
)
def test_poetry_predicate_and_resolved_edge_match_handwritten_boundary(tmp_path, raw, version, accepted):
    from poetry.core.constraints.version import Version, parse_constraint

    assert parse_constraint(raw).allows(Version.parse(version)) is accepted
    content = POETRY + package("parent", extra='[package.dependencies]\nfoo="' + raw + '"\n') + package("foo", version)
    observed = run(tmp_path, content, "poetry")
    assert bool(observed["edges"]) is accepted
    assert observed["inventory_status"] == ("complete" if accepted else "partial")


def test_poetry_root_caret_compatibility_remains_explicit_unknown(tmp_path):
    observed = run(tmp_path, POETRY.replace(">=3.12", "^3.12") + package(), "poetry")
    root = observed["semantic_dimensions"]["environment_records"][0]
    assert root["requires_python"] == "^3.12" and root["constraint_dialect"] == "poetry-core-2.1.3"
    assert root["activation"] == "unknown"


def test_poetry_constraint_admission_bounds_terms_digits_and_payload():
    from evaluation.m046.static_poetry_constraints import constraint
    from evaluation.m046.static_inputs import InputRefusal

    for raw in (" || ".join(["1"] * 129), "1" * 129):
        with pytest.raises(InputRefusal, match="requirement-complexity-budget-exceeded"):
            constraint(raw)
    with pytest.raises(InputRefusal, match="invalid-lock-version-constraint") as failure:
        constraint("https://user:secret@example.invalid/project")
    assert "secret" not in str(failure.value)


def test_poetry_success_refusal_and_renderer_do_not_retain_customer_global_cache(tmp_path):
    from evaluation.m046.static_poetry_constraints import constraint, version
    from evaluation.m046.static_inputs import InputRefusal
    from poetry.core.constraints.version import parse_constraint
    from poetry.core.version.pep440.parser import PEP440Parser

    for index in range(25):
        constraint("^1." + str(index))
        version("1." + str(index))
        assert parse_constraint.cache_info().currsize == PEP440Parser.parse.cache_info().currsize == 0
    for raw in ("^1.2 || private-secret", "1" * 129):
        with pytest.raises(InputRefusal):
            constraint(raw)
        assert parse_constraint.cache_info().currsize == PEP440Parser.parse.cache_info().currsize == 0
    content = POETRY + package("parent", extra='[package.dependencies]\nfoo="^1.2"\n') + package("foo", "1.2.5")
    assert run(tmp_path, content, "poetry")["inventory_status"] == "complete"
    assert parse_constraint.cache_info().currsize == PEP440Parser.parse.cache_info().currsize == 0


@pytest.mark.parametrize(
    "style,header,control",
    [
        ("uv", UV, 'conflicts=[[{package="root",extra="a"},{package="root",extra="b"}]]\n'),
        ("uv", UV, "resolution-markers=[\"python_version < '3.14'\"]\n"),
        ("uv", UV, '[manifest]\noverrides=[{name="foo",specifier="==1"}]\n'),
        ("pdm", PDM.replace('["inherit_metadata"]', "[]"), ""),
        ("pdm", PDM, 'targets=[{platform="linux"}]\n'),
        ("poetry", POETRY, 'future-control="secret"\n'),
    ],
)
def test_unimplemented_resolver_environment_controls_are_not_ignored(style, header, control):
    document = parse(style + ".lock", (header + control + package(style=style)).encode(), style + "-lock")
    assert document.disposition == "unsupported" and document.packages == ()
    assert "secret" not in repr(document)


@pytest.mark.parametrize("style,header", [("poetry", POETRY), ("pdm", PDM), ("uv", UV)])
def test_unknown_package_field_and_unsafe_source_remain_payload_free(style, header):
    content = header + package(style=style, extra='path="../../private-secret"\n')
    document = parse(style + ".lock", content.encode(), style + "-lock")
    assert document.disposition == "unsupported" and document.packages == ()
    assert "private-secret" not in repr(document)


@pytest.mark.parametrize("style,header", [("poetry", POETRY), ("pdm", PDM), ("uv", UV)])
def test_structured_admission_and_deadline_bound_all_lock_adapters(style, header):
    content = (header + package(style=style)).encode()
    assert parse(style + ".lock", content, style + "-lock", deadline=0).disposition == "budget-exceeded"
    assert parse(style + ".lock", content, style + "-lock", max_records=1).disposition == "budget-exceeded"


@pytest.mark.parametrize("style,header", [("poetry", POETRY), ("pdm", PDM), ("uv", UV)])
def test_artifact_metadata_must_match_selected_package(style, header):
    content = header + package(style=style).replace("foo-1-py3-none-any.whl", "foo-2-py3-none-any.whl")
    document = parse(style + ".lock", content.encode(), style + "-lock")
    assert document.reason == "conflicting-lock-artifact-identity" and document.packages == ()


def test_supplied_poetry_bad_content_hash_is_malformed():
    document = parse("poetry.lock", (POETRY.replace(SHA, "fixture") + package()).encode(), "poetry-lock")
    assert document.reason == "invalid-lock-metadata-hash" and document.disposition == "malformed"


def test_pdm_missing_content_hash_and_artifacts_remain_partial(tmp_path):
    content = PDM.replace('content_hash="sha256:' + SHA + '"\n', "") + package(style="pdm").replace(
        artifact("foo", style="pdm"), ""
    )
    observed = run(tmp_path, content, "pdm")
    assert observed["inventory_status"] == "partial" and observed["packages"] == ["pypi:foo@1"]
    assert observed["semantic_dimensions"]["occurrences"][0]["activation"] == "unknown"


def test_discovery_keeps_independent_roots_and_include_ownership(tmp_path):
    for name in ("first", "second"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "pdm.lock").write_text(PDM + package(style="pdm"))
    (tmp_path / "requirements.txt").write_text("-r first/pdm.lock\n--unsupported\n")
    with Source(tmp_path) as source:
        observed = evaluate(source)
    assert observed["inventory_status"] == "partial"
    assert {row["root"] for row in observed["semantic_dimensions"]["occurrences"]} == {"second"}
