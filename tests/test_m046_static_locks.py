"""Typed lock inventory, provenance, graph ambiguity and refusal contracts."""

import json
from pathlib import Path

import pytest

from evaluation.m046.corpus import CORPUS
from evaluation.m046.run import compare, materialize, snapshot
from evaluation.m046.static_inputs import Source
from evaluation.m046.static_inventory import evaluate
from evaluation.m046.static_locks import parse


def pipfile(fields=None, **kwargs):
    data = {
        "_meta": {"pipfile-spec": 6, "hash": {"sha256": "a" * 64}, "requires": {}, "sources": []},
        "default": {"Foo_Bar": fields or {"version": "==1"}},
    }
    return parse("Pipfile.lock", json.dumps(data).encode(), "pipfile-lock", **kwargs)


def pylock(packages, header="", **kwargs):
    content = 'lock-version="1.0"\ncreated-by="fixture"\n' + header + packages
    return parse("pylock.toml", content.encode(), "pylock", **kwargs)


def package(name="foo", version="1", extra=""):
    return (
        '[[packages]]\nname="'
        + name
        + '"\nversion="'
        + version
        + '"\n'
        + extra
        + '\nwheels=[{url="https://packages.invalid/'
        + name
        + "-"
        + version
        + '-py3-none-any.whl", hashes={sha256="'
        + "a" * 64
        + '"}}]\n'
    )


@pytest.mark.parametrize(
    "fixture_id",
    [
        "python-pipfile",
        "python-pipfile-complete",
        "python-pylock",
        "python-pylock-complete",
        "python-pylock-variant",
        "python-pylock-variant-complete",
    ],
)
def test_typed_lock_matches_independent_full_contract(tmp_path, fixture_id):
    fixture = next(item for item in CORPUS if item["id"] == fixture_id)
    root = tmp_path / "source"
    materialize(fixture, root)
    before = snapshot(root)
    with Source(root) as source:
        observed = evaluate(source)
    differences = compare(fixture["expected"], observed)
    assert differences["full_contract_agreement"], differences
    assert before == snapshot(root)


def test_pipfile_markers_extras_hashes_and_names_are_typed():
    document = pipfile(
        {
            "version": "==1",
            "markers": 'python_version < "3.14"',
            "extras": ["Test_Group"],
            "hashes": ["sha256:" + "A" * 64],
        }
    )
    assert document.disposition == "parsed"
    (row,) = document.packages
    assert row.name == "foo-bar" and row.version == "1"
    assert row.marker == 'python_version < "3.14"' and row.extras == ("test-group",)
    assert row.hashes == ("sha256:" + "a" * 64,)
    assert row.locator == "/default/Foo_Bar" and row.declared_range == "==1"


@pytest.mark.parametrize("version", [">=1", "==1.*", "==1,>=0", "==1; os_name == 'posix'", "==" + "1" * 129])
def test_lock_selection_is_not_a_requirement_or_guessed_range(version):
    document = pipfile({"version": version})
    assert document.disposition in {"unsupported", "malformed", "budget-exceeded"}
    assert document.packages == ()


@pytest.mark.parametrize(
    "fields",
    [
        {"git": "https://user:secret@example.invalid/repo"},
        {"path": "../../private"},
        {"editable": True},
        {"future-control": "secret"},
    ],
)
def test_pipfile_unknown_or_source_entries_do_not_claim_complete(fields):
    document = pipfile({"version": "==1", **fields})
    assert document.disposition == "unsupported" and document.packages == ()
    assert "secret" not in repr(document) and "private" not in repr(document)


def test_json_duplicate_keys_and_constants_are_refused():
    duplicate = parse(
        "Pipfile.lock",
        b'{"_meta":{"pipfile-spec":6},"default":{"foo":{"version":"==1","version":"==2"}}}',
        "pipfile-lock",
    )
    assert duplicate.reason == "duplicate-lock-key" and duplicate.packages == ()
    constant = parse("Pipfile.lock", b'{"_meta":{"pipfile-spec":6},"default":{"foo":{"version":NaN}}}', "pipfile-lock")
    assert constant.reason == "invalid-lock-number" and constant.packages == ()


def test_pipfile_custom_group_collisions_are_not_silently_combined():
    content = json.dumps({"_meta": {"pipfile-spec": 6}, "Test_Group": {}, "test-group": {}}).encode()
    document = parse("Pipfile.lock", content, "pipfile-lock")
    assert document.reason == "duplicate-lock-group" and document.disposition == "malformed"


def test_lock_package_and_deadline_limits_clear_selections():
    document = pipfile(max_records=0)
    assert document.disposition == "budget-exceeded" and document.packages == ()
    assert document.reason == "lock-record-budget-exceeded"
    document = pylock(package(), deadline=0)
    assert document.reason == "input-deadline-exceeded" and document.packages == ()


def test_pylock_missing_source_preserves_fragment_without_complete_claim(tmp_path):
    (tmp_path / "pylock.toml").write_text(
        'lock-version="1.0"\ncreated-by="fixture"\n[[packages]]\nname="foo"\nversion="1"\n'
    )
    with Source(tmp_path) as source:
        observed = evaluate(source)
    assert observed["packages"] == ["pypi:foo@1"] and observed["inventory_status"] == "partial"
    assert observed["semantic_dimensions"]["inputs"][0]["reason"] == "missing-lock-source"


@pytest.mark.parametrize(
    "source",
    [
        'vcs={type="git",url="https://user:secret@example.invalid/repo",commit-id="abc"}',
        'directory={path="../../private"}',
        'archive={url="https://user:secret@example.invalid/source"}',
    ],
)
def test_pylock_unsupported_source_does_not_leak_payload(source):
    document = pylock('[[packages]]\nname="foo"\nversion="1"\n' + source + "\n")
    assert document.disposition == "unsupported" and document.packages == ()
    assert "secret" not in repr(document) and "private" not in repr(document)


@pytest.mark.parametrize(
    "header",
    [
        "environments=[\"python_version < '3.14'\"]\n",
        'extras=["test"]\n',
        'dependency-groups=["test"]\n',
        'default-groups=["runtime"]\n',
    ],
)
def test_pylock_unimplemented_environment_selection_remains_visible(header):
    document = pylock(package(), header)
    assert document.disposition == "unsupported" and document.reason == "unsupported-lock-environment"


def test_pylock_ambiguous_dependency_does_not_invent_an_edge(tmp_path):
    content = (
        'lock-version="1.0"\ncreated-by="fixture"\n'
        + package("root", extra='dependencies=[{name="foo"}]')
        + package("foo", "1", "marker=\"python_version < '3.14'\"")
        + package("foo", "2", "marker=\"python_version >= '3.14'\"")
    )
    (tmp_path / "pylock.toml").write_text(content)
    with Source(tmp_path) as source:
        observed = evaluate(source)
    assert observed["edges"] == [] and observed["inventory_status"] == "partial"
    assert "ambiguous-lock-dependency" in observed["refusal_codes"]
    assert observed["packages"] == ["pypi:foo@1", "pypi:foo@2", "pypi:root@1"]


def test_pylock_explicit_selector_preserves_root_and_edge_locator(tmp_path):
    (tmp_path / "service").mkdir()
    content = (
        'lock-version="1.0"\ncreated-by="fixture"\n'
        + package("root", extra='dependencies=[{name="foo",version="2"}]')
        + package("foo", "1", "marker=\"python_version < '3.14'\"")
        + package("foo", "2", "marker=\"python_version >= '3.14'\"")
    )
    (tmp_path / "service" / "pylock.ci.toml").write_text(content)
    with Source(tmp_path) as source:
        observed = evaluate(source)
    assert observed["edges"] == [("pypi:root@1", "pypi:foo@2")]
    (edge,) = observed["semantic_dimensions"]["relationships"]
    assert edge["root"] == "service" and edge["locator"] == "packages[0].dependencies[0]"
    assert edge["path"] == "service/pylock.ci.toml"


@pytest.mark.parametrize(
    "fields",
    [
        "hashes={}",
        'hashes={sha256="bad"}',
        'hashes={md5="' + "a" * 32 + '"}',
        'url="https://user:secret@example.invalid/a",hashes={sha256="' + "a" * 64 + '"}',
        'path="../../private",hashes={sha256="' + "a" * 64 + '"}',
    ],
)
def test_pylock_bad_or_unsafe_artifact_metadata_is_refused(fields):
    document = pylock(
        '[[packages]]\nname="foo"\nversion="1"\nwheels=[{'
        + ("" if fields.startswith(("url=", "path=")) else 'url="https://example.invalid/a",')
        + fields
        + "}]\n"
    )
    assert document.disposition in {"unsupported", "malformed"} and document.packages == ()
    assert "secret" not in repr(document) and "private" not in repr(document)


def test_pip_include_ownership_does_not_promote_a_lock_input(tmp_path):
    (tmp_path / "requirements.txt").write_text("-r Pipfile.lock\n--unsupported\n")
    (tmp_path / "Pipfile.lock").write_text('{"_meta":{"pipfile-spec":6},"default":{"foo":{"version":"==1"}}}')
    with Source(tmp_path) as source:
        observed = evaluate(source)
    assert observed["packages"] == [] and observed["inventory_status"] == "partial"


def test_pipfile_python_family_is_not_misreported_as_one_patch_version():
    content = json.dumps(
        {
            "_meta": {
                "pipfile-spec": 6,
                "hash": {"sha256": "a" * 64},
                "sources": [],
                "requires": {"python_version": "3.14", "python_full_version": "3.14.8"},
            },
            "default": {},
        }
    ).encode()
    document = parse("Pipfile.lock", content, "pipfile-lock")
    assert document.disposition == "parsed"
    assert document.environment == (
        ("/_meta/requires/python_version", "==3.14.*"),
        ("/_meta/requires/python_full_version", "==3.14.8"),
    )


@pytest.mark.parametrize("filename", ["wrong-1-py3-none-any.whl", "foo-2-py3-none-any.whl", "not-a-wheel"])
def test_pylock_explicit_artifact_filename_cannot_contradict_package_identity(filename):
    document = pylock(
        '[[packages]]\nname="foo"\nversion="1"\nwheels=[{name="'
        + filename
        + '",url="https://example.invalid/a",hashes={sha256="'
        + "a" * 64
        + '"}}]\n'
    )
    assert document.disposition == "malformed" and document.packages == ()


@pytest.mark.parametrize(
    "field", ['url="https://example.invalid/bar-2-py3-none-any.whl"', 'path="dist/bar-2-py3-none-any.whl"']
)
def test_pylock_fallback_artifact_filename_must_match_package(field):
    document = pylock(
        '[[packages]]\nname="foo"\nversion="1"\nwheels=[{' + field + ',hashes={sha256="' + "a" * 64 + '"}}]\n'
    )
    assert document.disposition == "malformed" and document.reason == "conflicting-lock-artifact-identity"


def test_pylock_filename_precedence_is_name_then_path_then_url():
    document = pylock(
        '[[packages]]\nname="foo"\nversion="1"\nwheels=[{name="foo-1-py3-none-any.whl",path="dist/bar-2-py3-none-any.whl",url="https://example.invalid/baz-3-py3-none-any.whl",hashes={sha256="'
        + "a" * 64
        + '"}}]\n'
    )
    assert document.disposition == "parsed"
    document = pylock(
        '[[packages]]\nname="foo"\nversion="1"\nwheels=[{path="dist/foo-1-py3-none-any.whl",url="https://example.invalid/bar-2-py3-none-any.whl",hashes={sha256="'
        + "a" * 64
        + '"}}]\n'
    )
    assert document.disposition == "parsed"


def test_lock_admission_charges_packages_edges_artifacts_and_hash_records():
    document = pylock(package("root", extra='dependencies=[{name="foo"}]') + package("foo"))
    assert document.disposition == "parsed" and document.record_count == 7
    refused = pylock(package("root", extra='dependencies=[{name="foo"}]') + package("foo"), max_records=6)
    assert refused.disposition == "budget-exceeded" and refused.packages == ()


def test_structured_lock_admission_budget_is_shared_across_inputs(tmp_path, monkeypatch):
    from evaluation.m046 import static_inventory

    monkeypatch.setattr(static_inventory, "MAX_OCCURRENCES", 5)
    for name in ("a", "b"):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "pylock.toml").write_text('lock-version="1.0"\ncreated-by="fixture"\n' + package(name))
    with Source(tmp_path) as source:
        observed = evaluate(source)
    assert observed["inventory_status"] == "partial"
    assert observed["packages"] == ["pypi:a@1"]
    assert "lock-record-budget-exceeded" in observed["refusal_codes"]


@pytest.mark.parametrize(
    "metadata", [{"hash": "invalid"}, {"hash": {"sha256": "bad"}}, {"requires": []}, {"sources": "invalid"}]
)
def test_invalid_provided_pipfile_metadata_is_not_a_usable_fragment(metadata):
    content = json.dumps({"_meta": {"pipfile-spec": 6, **metadata}, "default": {"foo": {"version": "==1"}}}).encode()
    document = parse("Pipfile.lock", content, "pipfile-lock")
    assert document.disposition == "malformed" and document.packages == ()


def test_overlapping_unconditional_lock_variants_have_unknown_selection(tmp_path):
    (tmp_path / "pylock.toml").write_text(
        'lock-version="1.0"\ncreated-by="fixture"\n' + package("foo", "1") + package("foo", "2")
    )
    with Source(tmp_path) as source:
        observed = evaluate(source)
    assert observed["inventory_status"] == "partial" and observed["packages"] == ["pypi:foo@1", "pypi:foo@2"]
    assert "overlapping-lock-variants" in observed["refusal_codes"]
    assert all(row["activation"] == "unknown" for row in observed["semantic_dimensions"]["occurrences"])
    assert observed["semantic_dimensions"]["fidelity"]["environment"] == "unknown"
