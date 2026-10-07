"""Pinned lock grammar boundaries and maintained Poetry constraint grammar."""

import pytest
from sourcebastion.inventory.python_locks import parse

SHA = "a" * 64

POETRY = '[metadata]\nlock-version="2.1"\npython-versions=">=3.12"\ncontent-hash="' + SHA + '"\n'

PDM = (
    '[metadata]\nlock_version="4.5.0"\ngroups=["default","test"]\nstrategy=["inherit_metadata"]\ncontent_hash="sha256:'
    + SHA
    + '"\n'
)

UV = 'version=1\nrevision=3\nrequires-python=">=3.12"\n'

SOURCE = 'source={registry="https://pypi.org/simple"}\n'


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


def test_poetry_constraint_admission_bounds_terms_digits_and_payload():
    from sourcebastion.inventory.poetry_constraints import constraint
    from sourcebastion.inventory.inputs import InputRefusal

    for raw in (" || ".join(["1"] * 129), "1" * 129):
        with pytest.raises(InputRefusal, match="requirement-complexity-budget-exceeded"):
            constraint(raw)
    with pytest.raises(InputRefusal, match="invalid-lock-version-constraint") as failure:
        constraint("https://user:secret@example.invalid/project")
    assert "secret" not in str(failure.value)


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
    document = parse(style + ".lock", (header + control + package(style=style)).encode(), "python-" + style + "-lock")
    assert document.disposition == "unsupported" and document.packages == ()
    assert "secret" not in repr(document)


@pytest.mark.parametrize("style,header", [("poetry", POETRY), ("pdm", PDM), ("uv", UV)])
def test_unknown_package_field_and_unsafe_source_remain_payload_free(style, header):
    content = header + package(style=style, extra='path="../../private-secret"\n')
    document = parse(style + ".lock", content.encode(), "python-" + style + "-lock")
    assert document.disposition == "unsupported" and document.packages == ()
    assert "private-secret" not in repr(document)


@pytest.mark.parametrize("style,header", [("poetry", POETRY), ("pdm", PDM), ("uv", UV)])
def test_structured_admission_and_deadline_bound_all_lock_adapters(style, header):
    content = (header + package(style=style)).encode()
    assert parse(style + ".lock", content, "python-" + style + "-lock", deadline=0).disposition == "budget-exceeded"
    assert parse(style + ".lock", content, "python-" + style + "-lock", max_records=1).disposition == "budget-exceeded"


@pytest.mark.parametrize("style,header", [("poetry", POETRY), ("pdm", PDM), ("uv", UV)])
def test_artifact_metadata_must_match_selected_package(style, header):
    content = header + package(style=style).replace("foo-1-py3-none-any.whl", "foo-2-py3-none-any.whl")
    document = parse(style + ".lock", content.encode(), "python-" + style + "-lock")
    assert document.reason == "conflicting-lock-artifact-identity" and document.packages == ()


def test_supplied_poetry_bad_content_hash_is_malformed():
    document = parse("poetry.lock", (POETRY.replace(SHA, "fixture") + package()).encode(), "python-poetry-lock")
    assert document.reason == "invalid-lock-metadata-hash" and document.disposition == "malformed"
