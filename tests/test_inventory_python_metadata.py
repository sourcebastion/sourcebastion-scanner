"""Distribution observations cannot invent installation ownership or children."""

import hashlib

import pytest

from sourcebastion.inventory.compose_source import compose_source
from sourcebastion.inventory.contract import Environment, Producer, canonical_bytes
from sourcebastion.inventory.inputs import InputRefusal, Source
from sourcebastion.inventory.python_metadata import parse
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256

PATH = "site-packages/my_App-1.0.dist-info/METADATA"
BASE = "Metadata-Version: 2.3\nName: my-App\nVersion: 1.0\n"


def files(root, content, path=PATH):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content if isinstance(content, bytes) else content.encode())


def run(root, *, config=None, environment=None):
    config = config or DiscoveryConfig()
    with Source(root) as source:
        return compose_source(
            source,
            source_sha256="a" * 64,
            producer=Producer(
                name="test",
                version="1",
                code_sha256="a" * 64,
                registry_sha256=REGISTRY_SHA256,
                config_sha256=config.sha256,
            ),
            config=config,
            environment=environment,
        )


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_observed_distribution_has_no_interpreter_root_scope_or_child_selection(tmp_path, newline):
    text = (
        BASE + 'Requires-Dist: dep[extra]>=1; python_version < "4"\n'
        "Requires-Dist: exact==v2.0\nRequires-Python: >=3.12\nProvides-Extra: test\n"
        "Dynamic: Requires-Dist\n\nLong body with Requires-Dist: never-a-header\n"
    ).replace("\n", newline)
    files(tmp_path, text)
    result = run(tmp_path, environment=Environment(policy="explicit-target", python_version="3.14.8"))
    assert result.stages.inventory == "complete"
    assert len(result.occurrences) == 1 and not result.relationships
    row = result.occurrences[0]
    assert (row.name, row.selected_version, row.purl) == ("my-app", "1.0", "pkg:pypi/my-app@1.0")
    assert row.evidence_kind == "installed" and row.root_id is row.installed_environment_id is None
    assert row.activation == row.directness == "unknown" and row.scopes == ("unknown",)
    assert not result.roots and not result.installed_environments
    assert {d.name for d in result.declarations} == {"dep", "exact"}
    dep, exact = sorted(result.declarations, key=lambda r: r.name)
    assert dep.marker == 'python_version < "4"' and dep.extras == ("extra",)
    assert dep.exact_version is None and exact.exact_version == "2.0"
    assert all(d.analysis_scope_id == row.analysis_scope_id and d.root_id is None for d in result.declarations)
    assert len(result.applicability) == 1 and result.applicability[0].expression == ">=3.12"
    assert {r.reason for r in result.losses} == {
        "installed-environment-unassessed",
        "metadata-provided-extra-unassessed",
        "metadata-dynamic-information-unprojected",
    }
    assert result.coverage.graph == "partial" and result.coverage.environment == "unknown"
    (covered,) = result.coverage.inputs
    assert covered.source_sha256 == hashlib.sha256(text.encode()).hexdigest()
    assert covered.analysis_scope_ids == (row.analysis_scope_id,) and not covered.installed_environment_ids
    assert canonical_bytes(result) == canonical_bytes(run(tmp_path, environment=result.environment))


def test_folded_requirement_and_long_description_are_not_dropped(tmp_path):
    files(tmp_path, BASE + "Requires-Dist: dep\n >=1\n\n" + "documentation " * 5000)
    result = run(tmp_path)
    assert len(result.occurrences) == len(result.declarations) == 1
    assert result.declarations[0].name == "dep" and result.declarations[0].declared_range.strip() == ">=1"


@pytest.mark.parametrize(
    "text",
    [
        BASE + "not a header\nRequires-Dist: hidden==1\n\n",
        " orphaned continuation\n" + BASE,
        BASE + "Name: duplicate\n\n",
        BASE + "Version: 2\n\n",
        BASE.replace("2.3", "999.0") + "\n",
        BASE.replace("my-App", "different") + "\n",
        BASE.replace("Version: 1.0", "Version: 2.0") + "\n",
        BASE + "Requires-Dist: invalid >!1\n\n",
        BASE + "Requires-Python: what\n\n",
        BASE + "Unexpected-Metadata: ignored?\n\n",
        BASE + "Requires-Dist: hidden\x00==1\n\n",
        BASE.replace("Metadata-Version: 2.3", "Metadata-Version: 1.0") + "\n",
    ],
)
def test_uncertain_input_retains_independent_pip_without_metadata_authority(tmp_path, text):
    files(tmp_path, text)
    files(tmp_path, "pip==26.0.1\n", "requirements.txt")
    result = run(tmp_path)
    assert result.stages.inventory == "partial"
    assert [r.name for r in result.occurrences] == ["pip"]
    row = next(r for r in result.coverage.inputs if r.source_path == PATH)
    assert row.disposition in {"failed", "unsupported"} and row.source_sha256


@pytest.mark.parametrize(
    "field,value",
    [
        ("Version", "1" * 129),
        ("Requires-Python", ">=" + "1" * 129),
        ("Requires-Dist", "dep; " + "(" * 33 + 'python_version > "3"' + ")" * 33),
        ("License-Expression", "(" * 33 + "MIT" + ")" * 33),
        ("Requires-Dist", "dep" + " " * 17000),
    ],
)
def test_eager_validation_complexity_refuses_before_authority(tmp_path, field, value):
    text = BASE.replace("Version: 1.0\n", "") if field == "Version" else BASE
    files(tmp_path, text + field + ": " + value + "\n\n")
    result = run(tmp_path)
    assert result.stages.inventory == "failed" and not result.occurrences
    assert any("budget" in reason for reason in result.coverage.refusal_codes)


@pytest.mark.parametrize("header", ["Requires: legacy (1.0)", "Requires-External: libssl", "Platform: windows"])
def test_deprecated_external_and_platform_controls_stay_explicit_partial(tmp_path, header):
    files(tmp_path, BASE + header + "\n\n")
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and len(result.occurrences) == 1
    assert result.coverage.inputs[0].reason == "metadata-control-unassessed"
    assert any(r.reason == "metadata-control-unassessed" for r in result.losses)


@pytest.mark.parametrize("path", ["my.egg-info", "my.egg-info/PKG-INFO"])
def test_egg_info_cannot_assert_installation(tmp_path, path):
    files(tmp_path, BASE + "\n", path)
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and not result.occurrences
    assert result.coverage.inputs[0].disposition == "unsupported"


def test_equal_purls_in_two_files_keep_separate_unknown_contexts(tmp_path):
    files(tmp_path, BASE + "\n")
    files(tmp_path, BASE + "\n", "other/my_App-1.0.dist-info/METADATA")
    result = run(tmp_path)
    assert len(result.occurrences) == len(result.analysis_scopes) == 2
    assert len({r.id for r in result.occurrences}) == 2
    assert len({r.purl for r in result.occurrences}) == 1
    assert all(r.root_id is r.installed_environment_id is None for r in result.occurrences)


def test_url_requirement_remains_a_redacted_declaration_not_selected_child(tmp_path):
    files(tmp_path, BASE + "Requires-Dist: dep @ https://user:secret@example.test/file.whl?token=private\n\n")
    result = run(tmp_path)
    assert len(result.occurrences) == len(result.declarations) == 1
    assert result.declarations[0].declared_range == "direct-reference"
    raw = canonical_bytes(result)
    assert all(value not in raw for value in (b"secret", b"private", b"example.test"))


def test_shared_check_refusal_propagates_from_parser():
    def check():
        raise InputRefusal("composition-check-budget-exceeded")

    with pytest.raises(InputRefusal, match="composition-check-budget-exceeded"):
        parse(PATH, (BASE + "\n").encode(), check=check)


def test_final_source_change_discards_selected_metadata_and_pip(tmp_path, monkeypatch):
    import sourcebastion.inventory.compose_metadata as adapter

    files(tmp_path, BASE + "\n")
    files(tmp_path, "pip==26.0.1\n", "requirements.txt")
    original = adapter.python_metadata.parse

    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        (tmp_path / PATH).write_text(BASE.replace("1.0", "2.0") + "\n")
        return result

    monkeypatch.setattr(adapter.python_metadata, "parse", changed)
    result = run(tmp_path)
    assert result.stages.inventory == "failed" and not result.occurrences
    assert any(reason.startswith("changed-") for reason in result.coverage.refusal_codes)


def test_invalid_utf8_and_ignored_metadata_are_visible(tmp_path):
    files(tmp_path, b"\xff")
    result = run(tmp_path)
    assert not result.occurrences and result.coverage.inputs[0].reason == "invalid-input-encoding"
    result = run(tmp_path, config=DiscoveryConfig(ignored=(PATH,)))
    assert not result.occurrences and any(r.disposition == "ignored" for r in result.coverage.inputs)


@pytest.mark.parametrize(
    "field,value",
    [
        ("Name", "x" * 513),
        ("Version", "1." * 260 + "1"),
        ("Requires-Dist", "x" * 513 + ">=1"),
        ("Requires-Dist", "dep[" + ",".join("extra" + str(i) for i in range(257)) + "]>=1"),
    ],
)
def test_unrepresentable_identity_refuses_only_that_input(tmp_path, field, value):
    text = BASE
    if field in {"Name", "Version"}:
        text = "\n".join(line for line in BASE.splitlines() if not line.startswith(field + ":")) + "\n"
    files(tmp_path, text + field + ": " + value + "\n\n")
    files(tmp_path, "pip==26.0.1\n", "requirements.txt")
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and [r.name for r in result.occurrences] == ["pip"]


@pytest.mark.parametrize("extra", ["Test_Extra", "test_extra", "test--extra"])
def test_new_metadata_extra_spelling_is_checked_before_normalization(tmp_path, extra):
    files(tmp_path, BASE + "Provides-Extra: " + extra + "\n\n")
    files(tmp_path, "pip==26.0.1\n", "requirements.txt")
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and [r.name for r in result.occurrences] == ["pip"]
    assert next(r for r in result.coverage.inputs if r.source_path == PATH).reason == "invalid-metadata-extra"


def test_old_metadata_extra_normalization_does_not_infer_selection(tmp_path):
    files(tmp_path, BASE.replace("2.3", "2.1") + "Provides-Extra: Test_Extra\n\n")
    result = run(tmp_path)
    assert len(result.occurrences) == 1 and not result.applicability
    assert any(r.reason == "metadata-provided-extra-unassessed" for r in result.losses)


@pytest.mark.parametrize("import_name", ["example", "example ; private"])
def test_ambiguous_cross_field_import_identity_refuses_input(tmp_path, import_name):
    files(tmp_path, BASE.replace("2.3", "2.5") + "Import-Name: " + import_name + "\nImport-Namespace: example\n\n")
    files(tmp_path, "pip==26.0.1\n", "requirements.txt")
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and [r.name for r in result.occurrences] == ["pip"]
    assert (
        next(r for r in result.coverage.inputs if r.source_path == PATH).reason
        == "conflicting-metadata-import-identity"
    )


@pytest.mark.parametrize("imports", ["Import-Name:\n", "Import-Name: example\nImport-Namespace: other\n"])
def test_valid_import_controls_keep_distribution_and_visible_identity_loss(tmp_path, imports):
    files(tmp_path, BASE.replace("2.3", "2.5") + imports + "\n")
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and len(result.occurrences) == 1
    assert any(r.dimension == "identity" and r.reason == "metadata-import-identity-unassessed" for r in result.losses)


def test_empty_namespace_is_invalid_and_old_metadata_cannot_borrow_new_field(tmp_path):
    for text in (BASE.replace("2.3", "2.5") + "Import-Namespace:\n\n", BASE + "Import-Name:\n\n"):
        files(tmp_path, text)
        result = run(tmp_path)
        assert result.stages.inventory == "partial" and not result.occurrences


def test_normalized_marker_expansion_refuses_only_that_input(tmp_path):
    prefix = "Requires-Dist: dep;" + 'os_name=="x" and ' * 127 + 'os_name=="'
    line = prefix + "a" * (16380 - len(prefix) - 1) + '"'
    assert len(line) == 16380
    files(tmp_path, BASE + line + "\n\n")
    files(tmp_path, "pip==26.0.1\n", "requirements.txt")
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and [r.name for r in result.occurrences] == ["pip"]
    assert not result.coverage.refusal_codes


def test_header_c1_control_is_an_input_refusal_not_global_canonical_failure(tmp_path):
    files(tmp_path, BASE + 'Requires-Dist: dep; os_name == "\u0086"\n\n')
    files(tmp_path, "pip==26.0.1\n", "requirements.txt")
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and [r.name for r in result.occurrences] == ["pip"]


def test_empty_python_requirement_means_no_condition(tmp_path):
    files(tmp_path, BASE + "Requires-Python:\n\n")
    result = run(tmp_path)
    assert len(result.occurrences) == 1 and not result.applicability


def test_physical_header_line_budget_includes_continuations(tmp_path, monkeypatch):
    import sourcebastion.inventory.python_metadata as parser

    monkeypatch.setattr(parser, "MAX_HEADERS", 4)
    files(tmp_path, BASE + "Requires-Dist: dep\n >=1\n\n")
    result = run(tmp_path)
    assert result.stages.inventory == "failed" and not result.occurrences
    assert "metadata-record-budget-exceeded" in result.coverage.refusal_codes
