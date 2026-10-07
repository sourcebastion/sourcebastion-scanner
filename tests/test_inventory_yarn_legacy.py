"""Actual maintained grammar and narrowed source mapping admission."""

import time
import subprocess
import pytest
from sourcebastion.inventory import yarn_legacy
from sourcebastion.inventory.inputs import InputRefusal


def read(content):
    return yarn_legacy.parse(content, deadline=time.monotonic() + 10, check=lambda: None)


BASE = b'# yarn lockfile v1\n\n"alpha@^1":\n  version "1.2.3"\n  dependencies:\n    beta "^2"\n'


def test_actual_upstream_grammar_and_alias_keys():
    result = read(BASE.replace(b'"alpha@^1":', b'"alpha@^1", "alpha@~1":'))
    (entry,) = result
    assert entry[0] == ("alpha@^1", "alpha@~1")
    assert entry[1]["version"] == "1.2.3"
    assert entry[1]["dependencies"] == {"beta": "^2"}


@pytest.mark.parametrize(
    "content",
    [
        BASE.replace(b'  version "1.2.3"', b'  version "1.2.3"\n  version "9.0.0"'),
        BASE + BASE.split(b"\n\n", 1)[1],
        b'# yarn lockfile v1\n"__proto__":\n  polluted true\n',
        BASE.replace(b'    beta "^2"', b'    beta "^2"\n    beta "^9"'),
        b'# yarn lockfile v1\n"alpha@^1", "alpha@^1":\n  version "1.0.0"\n',
    ],
)
def test_duplicate_and_unsafe_keys_refuse_without_raw_error(content):
    with pytest.raises(InputRefusal, match="yarn-legacy-parse-refused"):
        read(content)


def test_private_syntax_error_has_fixed_reason():
    with pytest.raises(InputRefusal) as error:
        read(b'# yarn lockfile v1\n"https://user:secret@example.invalid": {{{\n')
    assert "secret" not in str(error.value)


def test_shared_ledger_propagates_before_helper(monkeypatch):
    def stop():
        raise InputRefusal("composition-check-budget-exceeded")

    def launched(*args, **kwargs):
        raise AssertionError("helper launched after refusal")

    monkeypatch.setattr(subprocess, "run", launched)
    with pytest.raises(InputRefusal, match="composition-check-budget-exceeded"):
        yarn_legacy.parse(BASE, deadline=time.monotonic() + 10, check=stop)


def test_no_project_environment_is_forwarded(monkeypatch):
    monkeypatch.setenv("NODE_OPTIONS", "--require=/tmp/CUSTOMER")
    monkeypatch.setenv("NODE_PATH", "/tmp/CUSTOMER")
    assert read(BASE)[0][1]["version"] == "1.2.3"


def test_equal_record_contents_do_not_merge_separate_source_entries():
    source = b'# yarn lockfile v1\n"alpha@^1":\n  version "1.2.3"\n"alpha@~1":\n  version "1.2.3"\n'
    entries = read(source)
    assert len(entries) == 2
    assert entries[0][1] == entries[1][1]
    assert entries[0][0] != entries[1][0]


@pytest.mark.parametrize("replacement", ['"\\uD800"', '"\\uDC00"'])
def test_invalid_unicode_key_has_fixed_refusal(replacement):
    with pytest.raises(InputRefusal, match="yarn-legacy-parse-refused"):
        read(BASE.replace(b'"alpha@^1"', replacement.encode()))


def test_expired_deadline_never_launches_helper(monkeypatch):
    def launched(*args, **kwargs):
        raise AssertionError("helper launched after deadline")

    monkeypatch.setattr(subprocess, "run", launched)
    with pytest.raises(InputRefusal, match="yarn-parser-deadline-exceeded"):
        yarn_legacy.parse(BASE, deadline=time.monotonic() - 1, check=lambda: None)


def test_oversize_source_refused_before_decode():
    with pytest.raises(InputRefusal, match="input-file-budget-exceeded"):
        read(BASE + b" " * (2 * 1024 * 1024))
