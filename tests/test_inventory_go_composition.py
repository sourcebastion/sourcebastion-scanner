"""Unavailable Go selection is visible alongside independent language evidence."""

import hashlib
from sourcebastion.inventory import go_sources

from sourcebastion.inventory.compose_source import compose_source
from sourcebastion.inventory.contract import Producer
from sourcebastion.inventory.inputs import Source
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256


def run(root, *, runtime=None):
    config = DiscoveryConfig()
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
