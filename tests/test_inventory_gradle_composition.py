"""Source selection, uncertainty and refusal contracts for modern Gradle locks."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest

from sourcebastion.inventory import compose_gradle
from sourcebastion.inventory.compose_source import compose_source
from sourcebastion.inventory.contract import Inventory, InventoryLimits, Producer, canonical_bytes
from sourcebastion.inventory.inputs import Source
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256


def run(root, *, config=None, limits=None):
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
            limits=limits,
        )


def test_original_gradle_source_matches_pre_execution_full_record_expectation(tmp_path):
    checkout = Path(__file__).resolve().parents[1]
    document = json.loads((checkout / "evaluation/m046/canonical-source-expectations-v1.json").read_text())
    expected = next(row for row in document["cases"] if row["case"] == "java-gradle-lock")
    for row in expected["fixture_files"]:
        (tmp_path / row["path"]).write_text(row["utf8"])
    module_spec = importlib.util.spec_from_file_location(
        "gradle_expected_comparator", checkout / "scripts/verify-inventory-expectations.py"
    )
    comparator = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(comparator)
    result = run(tmp_path)
    comparator.compare(expected, json.loads(canonical_bytes(result)))
    assert Inventory.model_validate_json(canonical_bytes(result)) == result
    assert run(tmp_path) == result


def test_same_module_retains_disjoint_versions_and_separate_input_contexts(tmp_path):
    content = "g:a:1.0=testRuntime\ng:a:2.0=compileClasspath, runtimeClasspath\nempty=\n"
    for prefix in ("one", "two"):
        root = tmp_path / prefix
        root.mkdir()
        (root / "gradle.lockfile").write_text(content)
    result = run(tmp_path)
    assert len(result.occurrences) == 4 and len({row.id for row in result.occurrences}) == 4
    assert len({row.analysis_scope_id for row in result.occurrences}) == 2
    assert {row.selected_version for row in result.occurrences} == {"1.0", "2.0"}
    assert {row.scopes for row in result.occurrences} == {("testRuntime",), ("compileClasspath", "runtimeClasspath")}
    assert all(row.root_id is row.installed_environment_id is None for row in result.occurrences)
    assert all(row.directness == row.activation == "unknown" for row in result.occurrences)
    assert not result.roots and not result.relationships and not result.applications
    assert result.coverage.graph == result.coverage.environment == "unknown"


@pytest.mark.parametrize(
    "name,mapping",
    [
        ("gradle.lockfile", ()),
        ("buildscript-gradle.lockfile", ()),
        (".locks/scala.lock", ((".locks/scala.lock", "gradle-lock"),)),
    ],
)
def test_default_buildscript_and_reviewed_mapped_names_are_static_inputs(tmp_path, monkeypatch, name, mapping):
    def forbidden(*args, **kwargs):
        raise AssertionError("project command execution")

    monkeypatch.setattr(subprocess, "run", forbidden)
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("g:a:1.0=compileClasspath\nempty=\n")
    (tmp_path / "build.gradle").write_text("throw new RuntimeException('never execute')\n")
    result = run(tmp_path, config=DiscoveryConfig(mappings=mapping))
    (occurrence,) = result.occurrences
    assert occurrence.source.path == name and occurrence.selected_version == "1.0"
    assert occurrence.source.source_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    # The adjacent executable build configuration remains explicitly unassessed.
    assert result.stages.inventory == "partial"
    assert any(row.format == "gradle-manifest" and row.disposition == "unsupported" for row in result.coverage.inputs)


@pytest.mark.parametrize(
    "body",
    [
        "g:a:1.0=compileClasspath\ng:a:1.0=runtimeClasspath\nempty=\n",
        "g:a:1.0=compileClasspath\ng:a:2.0=compileClasspath\nempty=\n",
        "g:a:1.0=compileClasspath,compileClasspath\nempty=\n",
        "g:a:1.0=compileClasspath\nempty=compileClasspath\n",
        "empty=\ng:a:1.0=compileClasspath\n",
        "empty=\nempty=\n",
        "g:a:1.0=\nempty=\n",
    ],
)
def test_contradictory_input_grants_no_selected_prefix(tmp_path, body):
    (tmp_path / "gradle.lockfile").write_text(body)
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    result = run(tmp_path)
    assert result.stages.inventory == "partial"
    assert [(row.ecosystem, row.selected_version) for row in result.occurrences] == [("pypi", "26.0.1")]
    assert result.coverage.version_resolution == "partial"
    assert next(row for row in result.coverage.inputs if row.format == "gradle-lock").disposition == "failed"


@pytest.mark.parametrize(
    "body",
    [
        b"g:a:1.+=compileClasspath\nempty=\n",
        b"g:a:[1,2)=compileClasspath\nempty=\n",
        b"g:a:latest.release=compileClasspath\nempty=\n",
        b"g:a:${secret}=compileClasspath\nempty=\n",
        b"https://user:secret@outside.invalid/a:1=compileClasspath\nempty=\n",
        b"g:a:1.0\n",
        b"# comments only\n",
        b"",
        b"g:a:1.0=compileClasspath\n",
        b"g:a:1.0=compileClass\x00path\nempty=\n",
        b"\xff\nempty=\n",
    ],
)
def test_unsupported_and_malformed_sources_never_become_clean_empty(tmp_path, body):
    (tmp_path / "gradle.lockfile").write_bytes(body)
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and not result.occurrences
    assert result.coverage.enumeration == result.coverage.version_resolution == "partial"
    assert not any(value in canonical_bytes(result) for value in [b"secret", b"outside.invalid"])


def test_empty_configuration_is_located_uncertainty_not_project_absence(tmp_path):
    (tmp_path / "gradle.lockfile").write_text("# empty locked configuration\nempty=annotationProcessor\n")
    result = run(tmp_path)
    assert not result.occurrences and not result.roots and not result.relationships
    (scope,) = result.analysis_scopes
    assert scope.kind == "lock-input"
    (loss,) = result.losses
    assert loss.reason == "unassessed-empty-gradle-configurations" and loss.dimension == "scope"
    assert loss.source.locator == "line:2" and loss.occurrence_id is None
    assert result.coverage.environment == result.coverage.graph == "unknown"


def test_ignored_gradle_source_cannot_poison_independent_python(tmp_path):
    (tmp_path / "gradle.lockfile").write_bytes(b"\xff")
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    result = run(tmp_path, config=DiscoveryConfig(ignored=("gradle.lockfile",)))
    assert len(result.occurrences) == 1 and result.stages.inventory == "complete"
    assert next(row for row in result.coverage.inputs if row.source_path == "gradle.lockfile").disposition == "ignored"


def test_global_occurrence_refusal_clears_prior_independent_records(tmp_path):
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    (tmp_path / "gradle.lockfile").write_text("g:a:1.0=compileClasspath\nempty=\n")
    result = run(tmp_path, limits=InventoryLimits(occurrences=1))
    assert result.stages.inventory == "failed" and not result.occurrences and not result.declarations
    assert "gradle-occurrence-budget-exceeded" in result.coverage.refusal_codes


def test_global_semantic_refusal_clears_previously_retained_mixed_records(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    (tmp_path / "gradle.lockfile").write_text("g:a:1.0=compileClasspath\nempty=\n")
    original = compose_gradle.extend

    def exhausted(state):
        assert state.occurrences and state.declarations
        state.step(state.limits.semantic_checks)
        original(state)

    monkeypatch.setattr(compose_gradle, "extend", exhausted)
    result = run(tmp_path)
    assert result.stages.inventory == "failed" and not result.occurrences and not result.declarations
    assert "composition-check-budget-exceeded" in result.coverage.refusal_codes


def test_configuration_expansion_uses_global_refusal(tmp_path):
    configs = ",".join(f"configuration{i}" for i in range(65))
    (tmp_path / "gradle.lockfile").write_text(f"g:a:1.0={configs}\nempty=\n")
    result = run(tmp_path)
    assert result.stages.inventory == "failed" and not result.occurrences
    assert "gradle-configuration-budget-exceeded" in result.coverage.refusal_codes


def test_source_mutation_during_parsing_refuses_all_inventory(tmp_path, monkeypatch):
    path = tmp_path / "gradle.lockfile"
    path.write_text("g:a:1.0=compileClasspath\nempty=\n")
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    original = compose_gradle.gradle_locks.parse

    def changed(content, **kwargs):
        document = original(content, **kwargs)
        path.write_text("g:a:2.0=compileClasspath\nempty=\n# changed\n")
        return document

    monkeypatch.setattr(compose_gradle.gradle_locks, "parse", changed)
    result = run(tmp_path)
    assert result.stages.inventory == "failed" and not result.occurrences and not result.declarations
    assert result.coverage.refusal_codes
