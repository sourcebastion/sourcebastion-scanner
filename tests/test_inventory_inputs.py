"""Descriptor and grammar boundaries for production inventory foundations."""

import hashlib
import os

import pytest

from sourcebastion.inventory.inputs import InputRefusal, Limits, Source
from sourcebastion.inventory.requirements import parse, target_path


def write(root, name, data=b"requests==2.32.3\n"):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def test_exact_source_hash_cache_and_hidden_determinism(tmp_path):
    root = tmp_path / "source"
    write(root, "z/requirements.txt")
    write(root, ".github/python-locks/build.txt", b"pip==26.0.1\n")
    with Source(root) as source:
        paths = [entry.path for entry in source.discover()]
        assert paths == [".github", ".github/python-locks", ".github/python-locks/build.txt", "z", "z/requirements.txt"]
        record = source.read(".github/python-locks/build.txt")
        assert record.content == b"pip==26.0.1\n"
        assert record.sha256 == hashlib.sha256(record.content).hexdigest()
        assert source.read(record.path) is record
        assert source.parsed_bytes == len(record.content)


def test_final_verification_retains_original_cached_bytes_without_duplication(tmp_path):
    write(tmp_path, "requirements.txt")
    with Source(tmp_path) as source:
        original = source.read("requirements.txt")
        charged = source.parsed_bytes
        source.validate()
        assert source.cache["requirements.txt"] is original
        assert source.parsed_bytes == charged


@pytest.mark.parametrize("version", ["9" * 4301, "1rc" + "9" * 4301, "1.post" + "9" * 4301, "9" * 4301 + "!1"])
def test_oversized_numeric_version_components_are_explicitly_refused(version):
    document = parse("requirements.txt", ("foo==" + version + "\n").encode())
    assert document.disposition == "budget-exceeded" and document.requirements == ()
    assert document.reason == "requirement-complexity-budget-exceeded"


@pytest.mark.parametrize("kind", ["leaf-link", "parent-link", "fifo"])
def test_real_symlinks_and_fifo_are_refused_without_read(tmp_path, kind):
    root = tmp_path / "source"
    root.mkdir()
    outside = write(tmp_path, "outside/requirements.txt", b"outside-secret==99\n")
    if kind == "leaf-link":
        (root / "requirements.txt").symlink_to(outside)
        name = "requirements.txt"
    elif kind == "parent-link":
        (root / "alias").symlink_to(outside.parent, target_is_directory=True)
        name = "alias/requirements.txt"
    else:
        os.mkfifo(root / "requirements.txt")
        name = "requirements.txt"
    with Source(root) as source:
        with pytest.raises(InputRefusal):
            source.read(name)
        assert source.parsed_bytes == 0 and not source.cache
        entries = list(source.discover())
        assert len(entries) == 1
        assert entries[0].kind == ("special" if kind == "fifo" else "symlink")


def test_root_replacement_is_refused(tmp_path):
    root = tmp_path / "source"
    write(root, "requirements.txt")
    with Source(root) as source:
        root.rename(tmp_path / "old-source")
        write(root, "requirements.txt", b"replacement==99\n")
        with pytest.raises(InputRefusal, match="changed-source-root"):
            source.read("requirements.txt")


def test_cached_file_replacement_is_refused(tmp_path):
    path = write(tmp_path, "nested/requirements.txt")
    with Source(tmp_path) as source:
        source.read("nested/requirements.txt")
        replacement = tmp_path / "nested/replacement"
        replacement.write_bytes(path.read_bytes())
        os.replace(replacement, path)
        with pytest.raises(InputRefusal, match="changed-input-path"):
            source.read("nested/requirements.txt")


def test_read_time_parent_swap_is_refused(tmp_path, monkeypatch):
    root = tmp_path / "source"
    path = write(root, "nested/requirements.txt")
    replacement = tmp_path / "replacement"
    write(replacement, "requirements.txt", path.read_bytes())
    real_read = os.read
    swapped = False

    def replace_parent(fd, size):
        nonlocal swapped
        data = real_read(fd, size)
        if not swapped and data:
            (root / "nested").rename(root / "old-nested")
            replacement.rename(root / "nested")
            swapped = True
        return data

    with Source(root) as source:
        monkeypatch.setattr(os, "read", replace_parent)
        with pytest.raises(InputRefusal):
            source.read("nested/requirements.txt")
        assert source.parsed_bytes == 0 and not source.cache


@pytest.mark.parametrize("extra", [0, 1])
def test_file_byte_boundary(tmp_path, extra):
    write(tmp_path, "requirements.txt", b"x" * (16 + extra))
    with Source(tmp_path, Limits(file_bytes=16)) as source:
        if extra:
            with pytest.raises(InputRefusal, match="input-file-budget-exceeded"):
                source.read("requirements.txt")
        else:
            assert len(source.read("requirements.txt").content) == 16


def test_unique_input_aggregate_boundary_and_cache(tmp_path):
    write(tmp_path, "a.txt", b"1234")
    write(tmp_path, "b.txt", b"5678")
    write(tmp_path, "c.txt", b"9")
    with Source(tmp_path, Limits(total_bytes=8)) as source:
        source.read("a.txt")
        source.read("a.txt")
        source.read("b.txt")
        with pytest.raises(InputRefusal, match="input-total-budget-exceeded"):
            source.read("c.txt")
        assert source.parsed_bytes == 8


@pytest.mark.parametrize("count", [3, 4])
def test_real_traversal_entry_boundary(tmp_path, count):
    for index in range(count):
        write(tmp_path, f"{index}.txt")
    with Source(tmp_path, Limits(entries=3)) as source:
        if count == 3:
            assert len(list(source.discover())) == 3
        else:
            iterator = source.discover()
            with pytest.raises(InputRefusal, match="input-traversal-budget-exceeded"):
                next(iterator)
        assert source.traversal_entries == 3


def test_include_reads_cannot_bypass_depth_budget(tmp_path):
    write(tmp_path, "a/b/requirements.txt")
    with Source(tmp_path, Limits(depth=1)) as source:
        with pytest.raises(InputRefusal, match="input-depth-budget-exceeded"):
            source.read("a/b/requirements.txt")
        assert [(e.path, e.kind) for e in source.discover()] == [("a", "directory"), ("a/b", "depth-omission")]


def test_deadline_refuses_cached_and_traversal_work(tmp_path):
    write(tmp_path, "requirements.txt")
    with Source(tmp_path) as source:
        source.read("requirements.txt")
        source.deadline = 0
        with pytest.raises(InputRefusal, match="input-deadline-exceeded"):
            source.read("requirements.txt")
        with pytest.raises(InputRefusal, match="input-deadline-exceeded"):
            list(source.discover())


@pytest.mark.parametrize("path", ["../outside.txt", "/outside.txt", "a/../../outside.txt", "bad\x00file", "a\\b"])
def test_raw_path_refusals(tmp_path, path):
    with Source(tmp_path) as source:
        with pytest.raises(InputRefusal):
            source.read(path)


@pytest.mark.parametrize(
    "path", ["requirements.txt", "deploy.in", "deps.pip", ".github/python-locks/build.txt", "scripts/python-build.in"]
)
def test_generic_exact_pins_have_same_semantics(path):
    document = parse(path, b"Typing_Extensions==4.12.2\n")
    assert document.disposition == "parsed"
    (record,) = document.requirements
    assert record.name == "typing-extensions" and record.exact_version == "4.12.2"
    assert record.specifier == "==4.12.2" and record.line == 1


def test_markers_extras_hashes_and_physical_location_survive():
    data = b'# heading\nrequests[socks]==2.32.3; python_version < "3.12" \\\n    --hash=sha256:' + b"A" * 64 + b"\n"
    document = parse("deploy.in", data)
    (record,) = document.requirements
    assert record.line == 2 and record.extras == ("socks",)
    assert record.marker == 'python_version < "3.12"'
    assert record.hashes == ("sha256:" + "a" * 64,)
    assert document.sha256 == hashlib.sha256(data).hexdigest()


def test_bom_is_in_source_hash_not_in_dependency_name():
    content = b"\xef\xbb\xbfrequests==2.32.3\n"
    document = parse("requirements.txt", content)
    assert document.sha256 == hashlib.sha256(content).hexdigest()
    assert document.requirements[0].name == "requests"


def test_range_is_not_a_selected_version():
    (record,) = parse("requirements.txt", b"requests>=2.31,<3\n").requirements
    assert record.exact_version is None and record.specifier == ">=2.31,<3"


@pytest.mark.parametrize(
    "path,content,reason",
    [
        ("meeting-notes.txt", b"Please discuss requests==2.32.3 next week.\n", "non-dependency-prose"),
        ("notes.txt", b"requests\n", "ambiguous-bare-declarations"),
        ("empty.in", b"# comment\n", "empty-candidate"),
    ],
)
def test_generic_false_positives_are_not_packages(path, content, reason):
    document = parse(path, content)
    assert document.disposition == "ignored" and document.reason == reason
    assert document.requirements == ()


@pytest.mark.parametrize("path", ["requirements.txt", "requirements-dev.txt", "requirements.test.in"])
def test_recognized_or_explicit_bare_declarations(path):
    (record,) = parse(path, b"requests\n").requirements
    assert record.exact_version is None
    assert parse("custom.config", b"requests\n", explicit=True).disposition == "parsed"


def test_reference_option_variants_remain_typed_data():
    data = b"-rbase.txt\n--requirement=locks/base.pip\n-c constraints.txt\n--constraint=constraints.txt\n"
    document = parse("requirements.txt", data)
    assert [(r.line, r.kind, r.target) for r in document.references] == [
        (1, "include", "base.txt"),
        (2, "include", "locks/base.pip"),
        (3, "constraint", "constraints.txt"),
        (4, "constraint", "constraints.txt"),
    ]
    assert document.requirements == ()


def test_inside_root_parent_reference_is_allowed():
    assert target_path("locks/production.txt", "../base.pip") == "base.pip"


@pytest.mark.parametrize(
    "target",
    ["../outside.txt", "/outside.txt", "https://user:token@example.test/deps.txt", "file:../deps.txt", "C:\\deps.txt"],
)
def test_escaping_reference_is_refused_without_sensitive_diagnostic(target):
    document = parse("requirements.txt", ("-r " + target + "\n").encode())
    assert document.disposition == "unsafe" and document.requirements == ()
    assert "user" not in document.reason and "token" not in repr(document)


@pytest.mark.parametrize(
    "data,reason",
    [
        (b"requests===\n", "invalid-requirement"),
        (b"requests==2.32.3 --hash=sha256:bad\n", "invalid-requirement-hash"),
        (b"requests==2.32.3,<2.32\n", "conflicting-requirement-specifiers"),
        (b"requests==2.32.3 \\\n", "unterminated-requirement-continuation"),
    ],
)
def test_malformed_input_does_not_emit_partial_packages(data, reason):
    document = parse("requirements.txt", data)
    assert document.disposition == "malformed" and document.reason == reason
    assert document.requirements == ()


def test_direct_references_and_options_cannot_leak_credentials():
    for content in (
        b"requests @ https://user:TOP_SECRET@example.test/a.whl?token=TOP_SECRET\n",
        b"--index-url https://user:TOP_SECRET@example.test/\nrequests==2.32.3\n",
    ):
        document = parse("requirements.txt", content)
        assert document.disposition == "unsupported" and not document.requirements
        assert "TOP_SECRET" not in repr(document)


def test_logical_line_budget_cannot_be_bypassed_with_continuations():
    content = b"requests==1 \\\n" * 2000
    document = parse("requirements.txt", content)
    assert document.disposition == "budget-exceeded" and document.reason == "requirement-line-budget-exceeded"


def test_comment_continuation_cannot_consume_dependency():
    document = parse("requirements.txt", b"# comment \\\nrequests==1\n")
    assert document.disposition == "parsed"
    (record,) = document.requirements
    assert record.name == "requests" and record.exact_version == "1" and record.line == 2


def test_token_continuation_does_not_insert_characters():
    (record,) = parse("requirements.txt", b"req\\\nuests==1\n").requirements
    assert record.name == "requests" and record.line == 1


def test_reference_option_tail_is_refused_before_url_retention():
    document = parse("requirements.txt", b'-r "base.txt" --index-url https://DEMO_TOKEN@example.test\n')
    assert document.disposition == "unsupported" and not document.requirements
    assert document.reason == "unsupported-reference-options"
    assert "DEMO_TOKEN" not in repr(document)
    assert document.references[0].target is None


@pytest.mark.parametrize("value", ["--hash", " --hash=sha256:" + "a" * 64 + " "])
def test_marker_hash_text_is_neither_rewritten_nor_an_option(value):
    document = parse("requirements.txt", f'requests==1; os_name == "{value}"\n'.encode())
    (record,) = document.requirements
    assert record.marker == f'os_name == "{value}"' and record.hashes == ()


def test_multiple_exact_specifiers_are_a_visible_conflict():
    document = parse("requirements.txt", b"requests==1,==2\n")
    assert document.disposition == "malformed" and document.reason == "conflicting-requirement-specifiers"
    assert document.requirements == ()


def test_nesting_overflow_is_a_stable_budget_refusal():
    content = ("requests==1; " + "(" * 900 + 'os_name == "posix"' + ")" * 900 + "\n").encode()
    document = parse("requirements.txt", content)
    assert document.disposition == "budget-exceeded" and document.reason == "requirement-complexity-budget-exceeded"


def test_record_and_deadline_limits_are_checked_before_acceptance():
    document = parse("requirements.txt", b"x\nx\nx\n", max_records=2)
    assert document.disposition == "budget-exceeded" and document.reason == "requirement-record-budget-exceeded"
    assert document.requirements == ()
    expired = parse("requirements.txt", b"requests==1\n", deadline=0)
    assert expired.disposition == "budget-exceeded" and expired.reason == "input-deadline-exceeded"


def test_environment_substitution_never_reads_host_environment(monkeypatch):
    monkeypatch.setenv("DEPENDENCIES", "SECRET_LOCAL_FILE")
    document = parse("requirements.txt", b"-r ${DEPENDENCIES}\n")
    assert document.disposition == "unsupported" and document.reason == "unsupported-environment-substitution"
    assert not document.references and "SECRET_LOCAL_FILE" not in repr(document)


def test_ambiguous_quoted_inline_comment_is_explicitly_unsupported():
    document = parse("requirements.txt", b'requests==1; os_name == " # quoted"\n')
    assert document.disposition == "unsupported" and document.reason == "unsupported-quoted-comment"
