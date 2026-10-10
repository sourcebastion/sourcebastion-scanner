"""Producer domains survive empty, skipped and unsupported input paths."""

import json

import pytest
from pydantic import ValidationError

from sourcebastion.inventory.contract import InputCoverage, canonical_bytes
from sourcebastion.inventory.row_projection import project_rows
from sourcebastion.inventory.registry import DiscoveryConfig
from tests.test_inventory_gradle_composition import run


def test_empty_unsupported_and_ignored_inputs_keep_independent_ecosystems(tmp_path):
    (tmp_path / "gradle.lockfile").write_text("empty=runtimeClasspath\n")
    (tmp_path / "pom.xml").write_text("<project/>\n")
    (tmp_path / "package.json").write_text('{"name":"skipped"}')
    result = run(tmp_path, config=DiscoveryConfig(ignored=("package.json",)))
    inputs = {row.source_path: row for row in result.coverage.inputs}
    assert not result.occurrences
    assert (inputs["gradle.lockfile"].ecosystem, inputs["gradle.lockfile"].enumeration) == ("maven", "complete")
    assert (inputs["pom.xml"].ecosystem, inputs["pom.xml"].disposition, inputs["pom.xml"].enumeration) == ("maven", "unsupported", "unknown")
    assert (inputs["package.json"].ecosystem, inputs["package.json"].disposition, inputs["package.json"].enumeration) == ("npm", "ignored", "unknown")
    assert result.stages.inventory == "partial"
    assert inputs["pom.xml"].root_ids == ()
    assert inputs["gradle.lockfile"].analysis_scope_ids


def test_multiple_evidenced_projects_retain_input_domains_and_root_bindings(tmp_path):
    for directory, package in (("left", "one"), ("right", "two")):
        root = tmp_path / directory
        root.mkdir()
        (root / "pyproject.toml").write_text(
            f'[project]\nname="{package}"\nversion="1.0"\ndependencies=["pip==26.0.1"]\n'
        )
    result = run(tmp_path)
    assert len(result.roots) == 2
    for row in result.coverage.inputs:
        assert row.ecosystem == "pypi" and row.enumeration == "complete"
        assert len(row.root_ids) == len(row.analysis_scope_ids) == 1
    assert len({row.root_ids for row in result.coverage.inputs}) == 2
    projected = project_rows(result, max_rows=1000, max_bytes=2**20, check=lambda: None)
    input_rows = [row for row in projected.rows if row.table == "input"]
    links = [dict(row.columns) for row in projected.rows if row.table == "input_context"]
    assert all(dict(row.columns)["ecosystem"] == "pypi" for row in input_rows)
    for row in input_rows:
        columns = dict(row.columns)
        evidence = json.loads(row.detail)
        assert {link["root_id"] for link in links if link["parent_id"] == columns["canonical_id"] and link["context_kind"] == "root"} == set(evidence["root_ids"])


@pytest.mark.parametrize("updates", [
    {"ecosystem": "npm"},
    {"enumeration": "complete"},
    {"ecosystem": "pypi", "enumeration": "complete", "enumeration_basis": "source-input", "disposition": "ignored"},
])
def test_invalid_or_cross_ecosystem_outcomes_are_refused(updates):
    with pytest.raises(ValidationError):
        InputCoverage(**{
            "source_path": "requirements.txt", "source_sha256": "a" * 64,
            "format": "pip-requirements", "parser": "test", "disposition": "parsed", "reason": "static-input",
            **updates,
        })


def test_older_canonical_inputs_keep_their_original_bytes_and_unknown_domains(tmp_path):
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    current = run(tmp_path)
    legacy_inputs = tuple(row.model_copy(update={"ecosystem": None, "enumeration": "unknown", "enumeration_basis": "unknown"}) for row in current.coverage.inputs)
    legacy = current.model_copy(update={"coverage": current.coverage.model_copy(update={"inputs": legacy_inputs})})
    raw = canonical_bytes(legacy)
    assert "ecosystem" not in json.loads(raw)["coverage"]["inputs"][0]
    from sourcebastion.inventory.canonical_reader import read_canonical
    import hashlib

    admitted = read_canonical(raw, expected_sha256=hashlib.sha256(raw).hexdigest(), check=lambda: None)
    assert admitted.coverage.inputs[0].ecosystem is None
    assert canonical_bytes(admitted) == raw
