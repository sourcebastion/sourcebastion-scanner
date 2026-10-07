"""Unavailable Go selection is visible alongside independent language evidence."""

import hashlib
import json

import pytest

from sourcebastion.inventory import compose_go, go_sources

from sourcebastion.inventory.compose_source import compose_source
from sourcebastion.inventory.contract import Inventory, Producer, canonical_bytes
from sourcebastion.inventory.inputs import Source
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256


def run(root, *, runtime=None, config=None):
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
            go_runtime=runtime,
        )


def test_missing_go_runtime_cannot_report_complete_empty_inventory(tmp_path):
    (tmp_path / "go.mod").write_text("module example.invalid/root\nrequire example.invalid/alpha v1.2.3\n")
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and result.coverage.version_resolution == "partial"
    assert not result.occurrences and not result.declarations
    assert result.coverage.inputs[0].reason == "go-parser-runtime-unavailable"


def test_go_checksum_history_does_not_promote_selected_version(tmp_path):
    (tmp_path / "go.sum").write_text("example.invalid/alpha v1.2.3 h1:" + "a" * 43 + "=\n")
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and not result.occurrences
    assert result.coverage.inputs[0].reason == "unassessed-go-checksum-history"


def test_unsupported_go_retains_independent_python_selected_pin(tmp_path):
    (tmp_path / "go.mod").write_text("module example.invalid/root\nrequire example.invalid/alpha v1.2.3\n")
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    result = run(tmp_path)
    assert result.stages.inventory == "partial"
    assert [(row.name, row.selected_version) for row in result.occurrences] == [("pip", "26.0.1")]
    assert result.coverage.version_resolution == "partial"


def test_runtime_loss_during_exec_error_clears_mixed_language_records(tmp_path, monkeypatch):
    binary = tmp_path / "trusted-helper"
    binary.write_bytes(b"\x7fELFsynthetic-controller-artifact")
    runtime = go_sources.Runtime(binary, hashlib.sha256(binary.read_bytes()).hexdigest())
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "go.mod").write_text("module example.invalid/root\nrequire example.invalid/alpha v1.2.3\n")
    (checkout / "requirements.txt").write_text("pip==26.0.1\n")

    def failed_exec(*args, **kwargs):
        binary.unlink()
        raise OSError("synthetic execution failure")

    monkeypatch.setattr(go_sources.subprocess, "run", failed_exec)
    result = run(checkout, runtime=runtime)
    assert result.stages.inventory == "failed" and not result.occurrences and not result.declarations
    assert "changed-go-parser-runtime" in result.coverage.refusal_codes


@pytest.fixture
def observed_go(monkeypatch):
    """Exercise projection from typed helper evidence; native parsing is separate."""

    def install(content, *, indirect=True, controls=()):
        start = content.index(b"require ")
        end = content.index(b"\n", start)
        observation = go_sources.decode(
            json.dumps(
                {
                    "schema_version": "sourcebastion.go-source-observation/1",
                    "parser": "golang.org/x/mod/modfile@v0.41.0",
                    "source_sha256": hashlib.sha256(content).hexdigest(),
                    "module": "example.invalid/root",
                    "requirements": [
                        {
                            "ordinal": 0,
                            "name": "example.invalid/alpha",
                            "minimum_version": "v1.2.3",
                            "indirect": indirect,
                            "line": 2,
                            "start_byte": start,
                            "end_byte": end,
                        }
                    ],
                    "unassessed_directives": sorted(controls),
                    "selected_versions": "unreported",
                    "graph": "unreported",
                }
            ).encode(),
            content,
            check=lambda: None,
        )

        def parse(actual, **kwargs):
            assert actual == content
            kwargs["check"]()
            return go_sources.Document("unsupported", "unresolved-go-module-selection-and-graph", observation)

        monkeypatch.setattr(go_sources, "parse", parse)

    return install


@pytest.mark.parametrize("indirect", [False, True])
def test_indirect_annotation_is_located_uncertainty_not_resolved_directness(tmp_path, observed_go, indirect):
    content = b"module example.invalid/root\nrequire example.invalid/alpha v1.2.3" + (
        b" // indirect\n" if indirect else b"\n"
    )
    (tmp_path / "go.mod").write_bytes(content)
    observed_go(content, indirect=indirect)
    result = run(tmp_path)
    occurrence = result.occurrences[0]
    assert occurrence.directness == "unknown" and occurrence.selected_version is None
    assert result.coverage.graph == "partial" and not result.relationships
    if indirect:
        (loss,) = result.losses
        assert (loss.reason, loss.dimension) == ("unassessed-go-indirect-annotation", "graph")
        assert loss.source == occurrence.source and loss.occurrence_id == occurrence.id
        assert loss.source.locator.startswith("require[0]:line[2]:bytes[")
    else:
        assert not result.losses


def test_named_controls_survive_without_projecting_private_targets(tmp_path, observed_go):
    content = (
        b"module example.invalid/root\nrequire example.invalid/alpha v1.2.3 // indirect\n"
        b"replace example.invalid/alpha => ../private-secret\nexclude example.invalid/beta v1.0.0\n"
        b"retract v1.0.0\ntoolchain go1.27.1\ntool example.invalid/tool\ngodebug panicnil=1\nignore ./generated\n"
    )
    expected = {
        "unassessed-replace-directive": "version",
        "unassessed-exclude-directive": "version",
        "unassessed-retract-directive": "version",
        "unassessed-toolchain-directive": "environment",
        "unassessed-tool-directive": "scope",
        "unassessed-godebug-directive": "environment",
        "unassessed-ignore-directive": "graph",
    }
    (tmp_path / "go.mod").write_bytes(content)
    observed_go(content, controls=expected)
    result = run(tmp_path)
    controls = [loss for loss in result.losses if loss.occurrence_id is None]
    assert {loss.reason: loss.dimension for loss in controls} == expected
    assert all(loss.source.path == "go.mod" and loss.source.locator == "module-input" for loss in controls)
    assert all(loss.source.source_sha256 == hashlib.sha256(content).hexdigest() for loss in result.losses)
    assert len(result.losses) == 8
    assert result.stages.inventory == "partial" and not result.relationships
    assert all(row.selected_version is None and row.activation == "unknown" for row in result.occurrences)
    encoded = canonical_bytes(result)
    assert b"private-secret" not in encoded
    assert canonical_bytes(Inventory.model_validate_json(encoded)) == encoded == canonical_bytes(run(tmp_path))


def test_identical_go_annotations_in_separate_projects_keep_distinct_sources(tmp_path, observed_go):
    content = b"module example.invalid/root\nrequire example.invalid/alpha v1.2.3 // indirect\n"
    for name in ("one", "two"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "go.mod").write_bytes(content)
    observed_go(content)
    result = run(tmp_path)
    assert len(result.losses) == 2 and len({loss.id for loss in result.losses}) == 2
    assert {loss.source.path for loss in result.losses} == {"one/go.mod", "two/go.mod"}
    assert {loss.occurrence_id for loss in result.losses} == {row.id for row in result.occurrences}
    assert len({row.root_id for row in result.occurrences}) == 2


def test_budget_refusal_clears_losses_with_other_composition_records(tmp_path, observed_go, monkeypatch):
    content = b"module example.invalid/root\nrequire example.invalid/alpha v1.2.3 // indirect\n"
    (tmp_path / "go.mod").write_bytes(content)
    (tmp_path / "requirements.txt").write_bytes(b"pip==26.0.1\n")
    observed_go(content)
    original_extend = compose_go.extend

    def exhausted_after_projection(state, runtime):
        original_extend(state, runtime)
        assert state.losses and state.occurrences and state.declarations
        state.step(state.limits.semantic_checks)

    monkeypatch.setattr(compose_go, "extend", exhausted_after_projection)
    result = run(tmp_path)
    assert result.stages.inventory == "failed"
    assert not result.losses and not result.occurrences and not result.declarations
    assert "composition-check-budget-exceeded" in result.coverage.refusal_codes
