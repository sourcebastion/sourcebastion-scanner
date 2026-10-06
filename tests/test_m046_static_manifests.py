"""Typed static manifest grammar and adversarial refusal contracts."""

import hashlib

import pytest

from evaluation.m046.static_manifests import parse
from evaluation.m046.static_inputs import Source
from evaluation.m046.static_inventory import evaluate
from evaluation.m046.corpus import CORPUS
from evaluation.m046.run import materialize, compare, snapshot


def parse_manifest(text, fmt="pep621", **kwargs):
    paths = {"pep621": "pyproject.toml", "setup-cfg": "setup.cfg", "setup-python-static": "setup.py"}
    return parse(paths[fmt], text.encode(), fmt, **kwargs)


def test_pep621_scopes_markers_extras_and_application_are_typed():
    text = '[project]\nname="my_app"\nversion="1.0"\nrequires-python=">=3.10"\ndependencies=["requests[socks]==2.32.3; os_name == \'posix\'"]\n[project.optional-dependencies]\nTest_Group=["pytest>=8"]\n[build-system]\nrequires=["setuptools==80.0"]\n'
    document = parse_manifest(text)
    assert document.disposition == "parsed" and document.sha256 == hashlib.sha256(text.encode()).hexdigest()
    assert document.application == "pypi:my-app@1.0"
    assert document.environment == (("project.requires-python", ">=3.10"),)
    assert [(row.locator, row.scope) for row in document.declarations] == [
        ("project.dependencies[0]", "runtime"),
        ("project.optional-dependencies.Test_Group[0]", "optional:test-group"),
        ("build-system.requires[0]", "build"),
    ]
    record = document.declarations[0].requirement
    assert record.extras == ("socks",) and record.marker == 'os_name == "posix"'
    assert document.declarations[1].requirement.exact_version is None


@pytest.mark.parametrize("field", ["dependencies", "optional-dependencies", "requires-python", "name"])
def test_dynamic_inventory_metadata_is_explicitly_unsupported(field):
    document = parse_manifest('[project]\nname="fixture"\ndynamic=["' + field + '"]\n')
    assert document.disposition == "unsupported" and document.declarations == ()
    assert document.reason == "unsupported-dynamic-metadata"


def test_duplicate_normalized_optional_groups_are_refused():
    document = parse_manifest(
        '[project]\nname="fixture"\nversion="1"\n[project.optional-dependencies]\nTest_Group=["foo==1"]\nTest-Group=["bar==2"]\n'
    )
    assert document.disposition == "malformed" and document.reason == "duplicate-manifest-group"


def test_unsupported_dependency_groups_do_not_claim_complete_manifest():
    document = parse_manifest('[dependency-groups]\ntest=["foo==1"]\n')
    assert document.disposition == "unsupported" and document.reason == "unsupported-dependency-groups"


def test_setup_cfg_dangling_single_requirement_keeps_marker():
    document = parse_manifest(
        '[metadata]\nname=fixture\n[options]\ninstall_requires=\n    foo==1; python_version < "3.12"\n', "setup-cfg"
    )
    assert document.disposition == "parsed"
    (row,) = document.declarations
    assert row.requirement.marker == 'python_version < "3.12"'
    assert row.locator == "options.install_requires[0]" and row.scope == "runtime"


def test_setup_cfg_one_line_semicolon_is_list_separator():
    document = parse_manifest("[options]\ninstall_requires=foo==1;bar==2\n", "setup-cfg")
    assert [row.requirement.name for row in document.declarations] == ["foo", "bar"]


def test_setup_cfg_does_not_interpolate_or_follow_file_directive():
    document = parse_manifest("[options]\ninstall_requires=file: requirements.txt\n", "setup-cfg")
    assert document.disposition == "unsupported" and document.declarations == ()
    assert document.reason == "unsupported-manifest-reference"
    interpolation = parse_manifest("[options]\ninstall_requires=%(secret)s\n", "setup-cfg")
    assert interpolation.disposition == "unsupported" and interpolation.reason == "unsupported-cfg-interpolation"


def test_static_ast_aliases_and_literal_constants_are_not_executed():
    document = parse_manifest(
        'from setuptools import setup as configure\nDEPS = ["foo==1"]\nconfigure(name="fixture", version="1.0", install_requires=DEPS, extras_require={"test": ["pytest==8"]})\n',
        "setup-python-static",
    )
    assert document.disposition == "parsed" and document.application == "pypi:fixture@1.0"
    assert [(row.requirement.name, row.scope) for row in document.declarations] == [
        ("foo", "runtime"),
        ("pytest", "optional:test"),
    ]


@pytest.mark.parametrize(
    "source",
    [
        "from setuptools import setup\nsetup(install_requires=compute())\n",
        'from setuptools import setup\nsetup = injected\nsetup(install_requires=["foo==1"])\n',
        'import os\nos.system("touch EXECUTED")\n',
        'from setuptools import setup\nif True:\n    setup(install_requires=["foo==1"])\n',
        'from setuptools import setup\nsetup(install_requires=[__import__("os").system("touch EXECUTED")])\n',
        'from setuptools import setup as x\nimport setuptools as x\nx(install_requires=["foo==1"])\n',
        'import setuptools as x\nfrom setuptools import setup as x\nx.setup(install_requires=["foo==1"])\n',
        'deps=["foo==1"]\nimport setuptools as deps\ndeps.setup(install_requires=deps)\n',
        'from .setuptools import setup\nsetup(install_requires=["foo==1"])\n',
    ],
)
def test_dynamic_ast_is_refused_without_execution(source):
    document = parse_manifest(source, "setup-python-static")
    assert document.disposition == "unsupported" and document.reason == "dynamic-metadata"
    assert document.declarations == ()


def test_ast_nesting_and_parser_record_limits_are_explicit():
    document = parse_manifest("x=" + "[" * 33 + "1" + "]" * 33, "setup-python-static")
    assert document.disposition == "budget-exceeded" and document.reason == "manifest-nesting-budget-exceeded"
    document = parse_manifest(
        '[project]\nname="fixture"\nversion="1"\ndependencies=["foo==1","bar==2"]\n', max_records=1
    )
    assert document.disposition == "budget-exceeded" and document.declarations == ()
    assert document.reason == "manifest-record-budget-exceeded"


def test_expired_manifest_parser_has_stable_deadline_refusal():
    document = parse_manifest('[project]\ndependencies=["foo==1"]\n', deadline=0)
    assert document.disposition == "budget-exceeded" and document.reason == "input-deadline-exceeded"


def test_manifest_direct_reference_never_emits_credentials():
    document = parse_manifest(
        '[project]\nname="fixture"\nversion="1"\ndependencies=["foo @ https://user:secret@example.invalid/foo.whl"]\n'
    )
    assert document.disposition == "unsupported" and document.declarations == ()
    assert document.reason == "unsupported-manifest-reference"
    assert "secret" not in repr(document)


@pytest.mark.parametrize(
    "fixture_id", ["python-pyproject", "python-pyproject-optional", "python-setup-cfg", "python-static-setup"]
)
def test_manifest_pipeline_matches_independent_full_oracle(tmp_path, fixture_id):
    fixture = next(fixture for fixture in CORPUS if fixture["id"] == fixture_id)
    root = tmp_path / "source"
    materialize(fixture, root)
    before = snapshot(root)
    with Source(root) as source:
        observed = evaluate(source)
    difference = compare(fixture["expected"], observed)
    assert difference["full_contract_agreement"], difference
    assert before == snapshot(root)


def test_refused_pip_parent_does_not_promote_manifest_child(tmp_path):
    (tmp_path / "requirements.txt").write_text("-r pyproject.toml\n--unknown-option\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nname="fixture"\nversion="1"\ndependencies=["foo==1"]\n')
    with Source(tmp_path) as source:
        observed = evaluate(source)
    assert observed["packages"] == [] and observed["inventory_status"] == "partial"


def test_manifest_sibling_pin_and_range_conflict_is_refused(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="fixture"\nversion="1"\ndependencies=["foo==1","foo>=2"]\n'
    )
    with Source(tmp_path) as source:
        observed = evaluate(source)
    assert observed["packages"] == [] and observed["inventory_status"] == "partial"
    assert "conflicting-root-declarations" in observed["refusal_codes"]


def test_setup_side_effects_are_not_executed_by_pipeline(tmp_path):
    (tmp_path / "setup.py").write_text(
        'from pathlib import Path\nPath("EXECUTED").write_text("bad")\nfrom setuptools import setup\nsetup(install_requires=["foo==1"])\n'
    )
    with Source(tmp_path) as source:
        observed = evaluate(source)
    assert observed["packages"] == [] and observed["inventory_status"] == "partial"
    assert not (tmp_path / "EXECUTED").exists()


def test_oversized_manifest_is_recorded_with_its_own_provenance(tmp_path):
    from evaluation.m046.static_inputs import Limits

    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies=["foo==1"]\n')
    with Source(tmp_path, Limits(file_bytes=8)) as source:
        observed = evaluate(source)
    assert observed["inventory_status"] == "partial" and observed["packages"] == []
    (record,) = observed["semantic_dimensions"]["inputs"]
    assert record["path"] == "pyproject.toml" and record["disposition"] == "budget-exceeded"
    assert record["reason"] == "input-file-budget-exceeded"


def test_changed_input_read_refuses_other_retained_selections(tmp_path, monkeypatch):
    from evaluation.m046.static_inputs import InputRefusal

    (tmp_path / "requirements.txt").write_text("foo==1\n")
    (tmp_path / "z.txt").write_text("bar==2\n")
    original = Source.read

    def changed(source, path, **kwargs):
        if path == "z.txt":
            raise InputRefusal("changed-input-bytes")
        return original(source, path, **kwargs)

    monkeypatch.setattr(Source, "read", changed)
    with Source(tmp_path) as source:
        observed = evaluate(source)
    assert observed["inventory_status"] == "failed" and observed["packages"] == []
    assert observed["refusal_codes"] == ["changed-input-bytes"]


def test_cfg_original_group_case_is_retained_in_locator():
    document = parse_manifest("[options.extras_require]\nTest_Group=foo==1\n", "setup-cfg")
    (declaration,) = document.declarations
    assert declaration.locator == "options.extras_require.Test_Group[0]"
    assert declaration.scope == "optional:test-group"


def test_cfg_inherited_defaults_do_not_invent_source_locators():
    document = parse_manifest("[DEFAULT]\ninstall_requires=foo==1\n[options]\n", "setup-cfg")
    assert document.disposition == "unsupported" and document.declarations == ()
    assert document.reason == "unsupported-cfg-defaults"


@pytest.mark.parametrize("version", ["1,>=0", "1; os_name == 'posix'", "1.*", "1 --hash=sha256:" + "a" * 64])
def test_application_version_is_a_version_not_a_requirement(version):
    import json

    document = parse_manifest('[project]\nname="fixture"\nversion=' + json.dumps(version) + "\n")
    assert document.disposition == "malformed" and document.application is None
    assert document.reason == "invalid-manifest-version"


@pytest.mark.parametrize("key", ["install-requires", "Install_Requires"])
def test_cfg_legacy_option_normalization_preserves_original_locator(key):
    document = parse_manifest("[options]\n" + key + "=foo==1\n", "setup-cfg")
    (declaration,) = document.declarations
    assert declaration.requirement.name == "foo"
    assert declaration.locator == "options." + key + "[0]"


def test_cfg_normalized_option_collision_is_not_silently_overwritten():
    document = parse_manifest("[options]\ninstall_requires=foo==1\ninstall-requires=bar==2\n", "setup-cfg")
    assert document.disposition == "malformed" and document.reason == "duplicate-cfg-option"


def test_cfg_unsupported_dependency_option_is_visible():
    document = parse_manifest("[options]\nextras_require=file: extras.txt\n", "setup-cfg")
    assert document.disposition == "unsupported" and document.reason == "unsupported-cfg-option"


@pytest.mark.parametrize(
    "tool,key",
    [
        ("poetry", "group.dev.dependencies"),
        ("pdm", "dev-dependencies"),
        ("uv", "dev-dependencies"),
        ("setuptools", "dynamic"),
    ],
)
def test_tool_dependency_sections_beside_pep621_are_not_silently_skipped(tool, key):
    document = parse_manifest(
        '[project]\nname="fixture"\nversion="1"\ndependencies=["foo==1"]\n[tool.' + tool + "." + key + ']\nbar="2"\n'
    )
    assert document.disposition == "unsupported" and document.declarations == ()
    assert document.reason == "unsupported-tool-dependencies"


@pytest.mark.parametrize(
    "text,reason",
    [
        ('[project]\nversion="1"\ndependencies=["foo==1"]\n', "invalid-project-metadata"),
        ('[project]\nname="fixture"\ndependencies=["foo==1"]\n', "invalid-project-metadata"),
        ('[build-system]\nbuild-backend="setuptools.build_meta"\n', "invalid-build-metadata"),
        ('[project]\nname="fixture"\nversion="1"\ndynamic=["unknown"]\n', "invalid-dynamic-metadata"),
        (
            '[project]\nname="fixture"\nversion="1"\ndynamic=["description", "description"]\n',
            "invalid-dynamic-metadata",
        ),
    ],
)
def test_inventory_relevant_invalid_metadata_is_explicit(text, reason):
    document = parse_manifest(text)
    assert document.disposition == "malformed" and document.reason == reason


def test_optional_range_only_manifest_has_unknown_activation(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="fixture"\nversion="1"\n[project.optional-dependencies]\ntest=["foo>=1"]\n'
    )
    with Source(tmp_path) as source:
        observed = evaluate(source)
    assert observed["inventory_status"] == "partial" and observed["packages"] == []
    assert observed["semantic_dimensions"]["fidelity"]["environment"] == "conditional-unknown"


def test_duplicate_declarations_do_not_repeat_quadratic_selection_work():
    from evaluation.m046.static_manifest_records import render

    document = parse_manifest(
        '[project]\nname="fixture"\nversion="1"\ndependencies=[' + ",".join(['"foo==1"'] * 500) + "]\n"
    )
    assert document.disposition == "parsed"
    steps = 0

    def check():
        nonlocal steps
        steps += 1
        assert steps < 3000, "duplicate declarations must share selection work"

    result = render(document, ".", check)
    assert len(result["occurrences"]) == 500
    assert len({row["locator"] for row in result["occurrences"]}) == 500


@pytest.mark.parametrize(
    "key",
    [
        "override-dependencies",
        "constraint-dependencies",
        "build-constraint-dependencies",
        "exclude-dependencies",
        "extra-build-dependencies",
        "dependency-metadata",
        "future-dependency-control",
    ],
)
def test_uv_selection_controls_cannot_bypass_known_tool_registry(key):
    document = parse_manifest(
        '[project]\nname="fixture"\nversion="1"\ndependencies=["foo==1"]\n[tool.uv]\n' + key + '=["bar==2"]\n'
    )
    assert document.disposition == "unsupported" and document.declarations == ()
    assert document.reason == "unsupported-tool-dependencies"


@pytest.mark.parametrize("table", ["hatch.envs.test", "hatch.metadata.hooks.custom", "rye", "pixi.pypi-dependencies"])
def test_additional_recognized_python_tool_dependencies_are_visible(table):
    document = parse_manifest(
        '[project]\nname="fixture"\nversion="1"\ndependencies=["foo==1"]\n[tool.'
        + table
        + ']\ndependencies=["bar==2"]\n'
    )
    assert document.disposition == "unsupported" and document.reason == "unsupported-tool-dependencies"


def test_known_metadata_only_tool_configuration_does_not_hide_valid_declarations():
    document = parse_manifest(
        '[project]\nname="fixture"\nversion="1"\ndependencies=["foo==1"]\n[tool.setuptools]\npy-modules=["fixture"]\n[tool.pdm]\ndistribution=true\n[tool.black]\nline-length=110\n'
    )
    assert document.disposition == "parsed"
    assert [row.requirement.name for row in document.declarations] == ["foo"]


@pytest.mark.parametrize(
    "path,text",
    [
        (
            "pyproject.toml",
            '[project]\nname="fixture"\nversion="1"\ndependencies=["foo==1; python_version < \'3.14\'"]\n',
        ),
        ("setup.cfg", '[options]\ninstall_requires=\n    foo==1; python_version < "3.14"\n'),
        ("setup.py", "from setuptools import setup\nsetup(install_requires=[\"foo==1; python_version < '3.14'\"])\n"),
    ],
)
def test_marker_only_manifest_selection_keeps_unknown_activation(tmp_path, path, text):
    (tmp_path / path).write_text(text)
    with Source(tmp_path) as source:
        observed = evaluate(source)
    assert observed["packages"] == ["pypi:foo@1"]
    (row,) = observed["semantic_dimensions"]["occurrences"]
    assert row["marker"] == 'python_version < "3.14"' and row["activation"] == "unknown"
    assert observed["semantic_dimensions"]["fidelity"]["environment"] == "conditional-unknown"
