"""Controller state tests use explicit fake process captures, never Grype."""

import hashlib
import json
from threading import Event

import pytest

from sourcebastion.inventory.artifacts import ArtifactStore
from sourcebastion.inventory.budget import PipelineBudget
from sourcebastion.inventory.contract import InventoryLimits, Producer
from sourcebastion.inventory import dependency_job as job
from sourcebastion.inventory.inputs import Source
from sourcebastion.inventory.process_capture import Capture
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256
from tests.test_inventory_consumer_runtime import prepared


def exercise(tmp_path, monkeypatch, *, failure=None, deadline=None, cancelled=None):
    spec, _binary, root = prepared(tmp_path, monkeypatch)
    monkeypatch.setattr(job, "ADVISORIES", root)
    source_root, output = tmp_path / "source", tmp_path / "output"
    source_root.mkdir()
    (source_root / "requirements.in").write_text("pip==26.0.1\nrequests>=2\n")
    output.mkdir(mode=0o700)
    status = {
        "valid": True,
        "schemaVersion": spec.advisory_schema,
        "built": spec.advisory_built,
        "path": str(root / "6/vulnerability.db"),
    }
    captures = []
    if failure == "late-runtime-change":
        original_validate = ArtifactStore.validate
        final_guards = 0

        def change_binary_during_last_artifact_guard(store):
            nonlocal final_guards
            result = original_validate(store)
            if any(fact.name == "recovery.json" for fact in store.facts):
                final_guards += 1
                if final_guards == 2:
                    _binary.chmod(0o700)
                    _binary.write_bytes(b"changed-native-binary")
            return result

        monkeypatch.setattr(ArtifactStore, "validate", change_binary_during_last_artifact_guard)

    def fake_capture(command, **values):
        captures.append((command, values))
        values["budget"].check()
        name, store = values["stdout_name"], values["store"]
        if name == "grype-version.json":
            document = {"version": spec.version}
        elif name == "grype-status.json":
            document = dict(status)
            if failure == "status-path":
                document["path"] = "/outside/unbound/vulnerability.db"
        else:
            document = {
                "source": {"type": "sbom-file"},
                "descriptor": {"name": "grype", "version": spec.version, "db": {"status": status}},
                "matches": [],
            }
            if failure == "invalid-json":
                document = {"matches": []}
            if failure == "analysis-path":
                document["descriptor"]["db"]["status"] = dict(status, path="/outside/unbound/vulnerability.db")
            if failure == "runtime-change":
                (root / "6/vulnerability.db").chmod(0o600)
                (root / "6/vulnerability.db").write_bytes(b"changed")
        raw = json.dumps(document).encode()
        stdout = store.writer(name, maximum=values["stdout_maximum"])
        stderr = store.writer(values["stderr_name"], maximum=values["stderr_maximum"])
        stdout.write(raw)
        stderr.write(b"failure" if failure == "nonzero" and name == "grype.json" else b"")
        return Capture(7 if failure == "nonzero" and name == "grype.json" else 0, stdout.finish(), stderr.finish())

    monkeypatch.setattr(job, "_capture", fake_capture)
    config = DiscoveryConfig()
    with Source(source_root) as source:
        budget = PipelineBudget(source, config=config, deadline=deadline or source.deadline)
        with ArtifactStore(output, limits=InventoryLimits(), check=budget.check) as store:
            result = job.run_dependency(
                source,
                budget=budget,
                config=config,
                producer=Producer(
                    name="finite-test",
                    version="1",
                    code_sha256="a" * 64,
                    registry_sha256=REGISTRY_SHA256,
                    config_sha256=config.sha256,
                ),
                source_sha256="b" * 64,
                store=store,
                runtime=spec,
                cancelled=cancelled,
            )
            return result, json.loads(result.receipt), output, captures, budget.deadline


def test_fixed_controller_preserves_canonical_states_and_separates_parent_authority(tmp_path, monkeypatch):
    result, receipt, output, captures, deadline = exercise(tmp_path, monkeypatch)
    assert result.finalized and receipt["reason"] is None
    assert set(receipt["stages"].values()) == {"succeeded"}
    assert receipt["authority"] == "child-artifact-facts-only" and receipt["kernel_admission"] == "not_observed"
    assert receipt["execution"] == {"exit_code": 0, "lifecycle": "leader-reaped-only"}
    canonical = json.loads((output / "inventory.json").read_bytes())
    assert canonical["stages"]["matching"] == canonical["stages"]["export"] == "not-run"
    assert len(canonical["occurrences"]) == 2
    assert len(json.loads((output / "sbom.cdx.json").read_bytes())["components"]) == 1
    assert len(captures) == 3
    assert all(values["budget"] is captures[0][1]["budget"] for _command, values in captures)
    assert all(values["budget"].deadline == deadline for _command, values in captures)
    assert all(command[0].startswith("/proc/self/fd/") and values["pass_fds"] for command, values in captures)
    assert captures[-1][0][3].startswith("sbom:")
    assert all(values["environment"]["GRYPE_DB_AUTO_UPDATE"] == "false" for _command, values in captures)
    for fact in receipt["artifacts"]:
        raw = (output / fact["name"]).read_bytes()
        assert len(raw) == fact["bytes"] and hashlib.sha256(raw).hexdigest() == fact["sha256"]
    assert not (output / "execution.json").exists()
    configuration_raw = (output / "consumer-config.json").read_bytes()
    assert receipt["consumer"]["config_sha256"] == hashlib.sha256(configuration_raw).hexdigest()
    configuration = json.loads(configuration_raw)
    assert configuration["yaml_sha256"] == hashlib.sha256((output / "grype.yaml").read_bytes()).hexdigest()
    assert configuration["environment"] == captures[-1][1]["environment"]
    assert configuration["cwd"] == str(captures[-1][1]["cwd"])


@pytest.mark.parametrize(
    "failure,stage",
    [("nonzero", "consumer_execution"), ("invalid-json", "recovery"), ("runtime-change", "finalization")],
)
def test_later_failure_preserves_inventory_export_and_raw_diagnostic(tmp_path, monkeypatch, failure, stage):
    result, receipt, output, _captures, _deadline = exercise(tmp_path, monkeypatch, failure=failure)
    assert not result.finalized and receipt["stages"][stage] == "failed"
    assert receipt["stages"]["inventory"] == receipt["stages"]["export"] == "succeeded"
    assert (output / "inventory.json").is_file() and (output / "sbom.cdx.json").is_file()
    assert (output / "grype.json").is_file()
    assert json.loads((output / "inventory.json").read_bytes())["stages"]["matching"] == "not-run"
    if failure == "nonzero":
        assert receipt["execution"]["exit_code"] == 7 and (output / "grype.stderr").read_bytes() == b"failure"


def test_prelaunch_cancellation_records_no_runtime_or_composition_success(tmp_path, monkeypatch):
    cancelled = Event()
    cancelled.set()
    result, receipt, output, captures, _deadline = exercise(tmp_path, monkeypatch, cancelled=cancelled)
    assert not result.finalized and receipt["stages"]["runtime_admission"] == "failed"
    assert receipt["stages"]["composition"] == "not_run" and not captures
    assert not list(output.iterdir())


@pytest.mark.parametrize(
    "failure,stage",
    [("late-runtime-change", "finalization"), ("status-path", "runtime_admission"), ("analysis-path", "recovery")],
)
def test_runtime_custody_and_actual_database_paths_refuse_contradictions(tmp_path, monkeypatch, failure, stage):
    result, receipt, output, _captures, _deadline = exercise(tmp_path, monkeypatch, failure=failure)
    assert not result.finalized and receipt["stages"][stage] == "failed"
    if failure != "status-path":
        assert (output / "inventory.json").is_file() and (output / "sbom.cdx.json").is_file()
