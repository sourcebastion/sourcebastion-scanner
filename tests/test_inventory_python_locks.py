"""Source lock grammar, refusals, limits and artifact identity."""

import json
import pytest
from sourcebastion.inventory.python_locks import parse


def pipfile(fields=None, **kwargs):
    data = {
        "_meta": {"pipfile-spec": 6, "hash": {"sha256": "a" * 64}, "requires": {}, "sources": []},
        "default": {"Foo_Bar": fields or {"version": "==1", "hashes": ["sha256:" + "a" * 64]}},
    }
    return parse("Pipfile.lock", json.dumps(data).encode(), "python-pipfile-lock", **kwargs)


def pylock(packages, header="", **kwargs):
    content = 'lock-version="1.0"\ncreated-by="fixture"\n' + header + packages
    return parse("pylock.toml", content.encode(), "python-pylock", **kwargs)


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
        "python-pipfile-lock",
    )
    assert duplicate.reason == "duplicate-lock-key" and duplicate.packages == ()
    constant = parse(
        "Pipfile.lock", b'{"_meta":{"pipfile-spec":6},"default":{"foo":{"version":NaN}}}', "python-pipfile-lock"
    )
    assert constant.reason == "invalid-lock-number" and constant.packages == ()


def test_pipfile_custom_group_collisions_are_not_silently_combined():
    content = json.dumps({"_meta": {"pipfile-spec": 6}, "Test_Group": {}, "test-group": {}}).encode()
    document = parse("Pipfile.lock", content, "python-pipfile-lock")
    assert document.reason == "duplicate-lock-group" and document.disposition == "malformed"


def test_lock_package_and_deadline_limits_clear_selections():
    document = pipfile(max_records=0)
    assert document.disposition == "budget-exceeded" and document.packages == ()
    assert document.reason == "lock-record-budget-exceeded"
    document = pylock(package(), deadline=0)
    assert document.reason == "input-deadline-exceeded" and document.packages == ()


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
    document = parse("Pipfile.lock", content, "python-pipfile-lock")
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


@pytest.mark.parametrize(
    "metadata", [{"hash": "invalid"}, {"hash": {"sha256": "bad"}}, {"requires": []}, {"sources": "invalid"}]
)
def test_invalid_provided_pipfile_metadata_is_not_a_usable_fragment(metadata):
    content = json.dumps({"_meta": {"pipfile-spec": 6, **metadata}, "default": {"foo": {"version": "==1"}}}).encode()
    document = parse("Pipfile.lock", content, "python-pipfile-lock")
    assert document.disposition == "malformed" and document.packages == ()
