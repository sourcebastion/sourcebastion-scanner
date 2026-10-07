"""Exclusive retention, shared-budget refusal and immutable artifact stages."""

import hashlib
import json
import os

import pytest

from sourcebastion.inventory.artifacts import ArtifactStore
from sourcebastion.inventory.budget import PipelineBudget
from sourcebastion.inventory.contract import InventoryLimits, Producer
from sourcebastion.inventory.direct_pipeline import run_direct
from sourcebastion.inventory.inputs import InputRefusal, Source
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256


def roots(tmp_path):
    source, output = tmp_path / "source", tmp_path / "output"
    source.mkdir()
    output.mkdir(mode=0o700)
    return source, output


def producer(config):
    return Producer(
        name="test-controller",
        version="1",
        code_sha256="a" * 64,
        registry_sha256=REGISTRY_SHA256,
        config_sha256=config.sha256,
    )


def run(source, budget, config, store):
    return run_direct(
        source,
        budget=budget,
        config=config,
        producer=producer(config),
        source_sha256="b" * 64,
        store=store,
    )


def test_direct_pipeline_freezes_inventory_and_exports_without_promoting_matching(tmp_path):
    root, output = roots(tmp_path)
    (root / "requirements.in").write_text("pip==26.0.1\nrequests>=2\n")
    config = DiscoveryConfig()
    with Source(root) as source:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        with ArtifactStore(output, limits=InventoryLimits(), check=budget.check) as store:
            result = run(source, budget, config, store)
            assert result.finalized
            receipt = json.loads(result.receipt)
            assert receipt["authority"] == "child-artifact-facts-only"
            assert receipt["kernel_admission"] == "not_observed" and receipt["matching"] == "not_run"
            assert set(receipt["stages"].values()) == {"succeeded"}
            assert len(receipt["artifacts"]) == 2
            for fact in receipt["artifacts"]:
                raw = (output / fact["name"]).read_bytes()
                assert fact["sha256"] == hashlib.sha256(raw).hexdigest() and fact["bytes"] == len(raw)
            canonical = json.loads((output / "inventory.json").read_bytes())
            assert canonical["stages"]["export"] == canonical["stages"]["matching"] == "not-run"
            assert len(json.loads((output / "sbom.cdx.json").read_bytes())["components"]) == 1
            assert store.reserved_bytes == 65536 + sum(fact.bytes for fact in store.facts)
            assert not (output / "execution.json").exists()


def test_unsupported_input_remains_partial_not_empty_success(tmp_path):
    root, output = roots(tmp_path)
    (root / "Gemfile.lock").write_text("GEM\n  specs:\n    rake (13.2.1)\n")
    config = DiscoveryConfig()
    with Source(root) as source:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        with ArtifactStore(output, limits=InventoryLimits(), check=budget.check) as store:
            result = run(source, budget, config, store)
            receipt = json.loads(result.receipt)
            assert result.finalized and receipt["inventory_state"] == "partial"
            value = json.loads((output / "inventory.json").read_bytes())
            assert value["coverage"]["inputs"][0]["disposition"] == "unsupported"
            assert receipt["matching"] == "not_run"


def test_export_failure_preserves_exact_inventory_without_execution_success_file(tmp_path):
    root, output = roots(tmp_path)
    (root / "requirements.in").write_text("pip==26.0.1\n")
    config = DiscoveryConfig()
    with Source(root) as source:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        with ArtifactStore(output, limits=InventoryLimits(sbom_bytes=1), check=budget.check) as store:
            result = run(source, budget, config, store)
            receipt = json.loads(result.receipt)
            assert not result.finalized
            assert receipt["stages"]["inventory"] == "succeeded"
            assert receipt["stages"]["export"] == "failed"
            assert receipt["stages"]["source_validation"] == "not_run"
            assert [fact["name"] for fact in receipt["artifacts"]] == ["inventory.json"]
            assert json.loads((output / "inventory.json").read_bytes())["stages"]["export"] == "not-run"
            assert not (output / "execution.json").exists()


def test_final_source_change_refuses_authority_but_preserves_inventory_and_export(tmp_path, monkeypatch):
    root, output = roots(tmp_path)
    path = root / "requirements.txt"
    path.write_text("pip==26.0.1\n")
    config = DiscoveryConfig()
    with Source(root) as source:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        with ArtifactStore(output, limits=InventoryLimits(), check=budget.check) as store:
            original = store.put

            def put(name, content):
                fact = original(name, content)
                if name == "sbom.cdx.json":
                    path.write_text("pip==26.0.2\n")
                return fact

            monkeypatch.setattr(store, "put", put)
            result = run(source, budget, config, store)
            receipt = json.loads(result.receipt)
            assert not result.finalized and receipt["stages"]["source_validation"] == "failed"
            assert len(receipt["artifacts"]) == 2
            assert b"26.0.1" in (output / "inventory.json").read_bytes()


def test_exhausted_shared_budget_does_not_get_finalization_allowance(tmp_path):
    root, output = roots(tmp_path)
    config = DiscoveryConfig(semantic_checks=3)
    with Source(root) as source:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        with ArtifactStore(output, limits=InventoryLimits(semantic_checks=3), check=budget.check) as store:
            with pytest.raises(InputRefusal, match="pipeline-semantic-budget-exceeded"):
                run(source, budget, config, store)
            assert budget.refusal_reason == "pipeline-semantic-budget-exceeded"
            assert not list(output.iterdir())


@pytest.mark.parametrize("name", ["../inventory.json", "/inventory.json", "other.json", "a/inventory.json"])
def test_artifact_paths_are_fixed(tmp_path, name):
    tmp_path.chmod(0o700)
    with ArtifactStore(tmp_path, limits=InventoryLimits(), check=lambda: None) as store:
        with pytest.raises(ValueError, match="invalid-artifact-write"):
            store.put(name, b"data")


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o777])
def test_artifact_root_must_be_owner_only(tmp_path, mode):
    tmp_path.chmod(mode)
    with pytest.raises(InputRefusal, match="unsafe-artifact-root"):
        ArtifactStore(tmp_path, limits=InventoryLimits(), check=lambda: None)


def test_existing_artifact_or_unexpected_entry_refused_without_cleanup(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "inventory.json"
    path.write_bytes(b"original")
    with pytest.raises(InputRefusal, match="unexpected-artifact-entry"):
        ArtifactStore(tmp_path, limits=InventoryLimits(), check=lambda: None)
    assert path.read_bytes() == b"original"


def test_store_never_overwrites_successful_write(tmp_path):
    tmp_path.chmod(0o700)
    with ArtifactStore(tmp_path, limits=InventoryLimits(), check=lambda: None) as store:
        fact = store.put("inventory.json", b"original")
        with pytest.raises(ValueError, match="artifact-already-attempted"):
            store.put("inventory.json", b"replacement")
        assert store.facts == (fact,) and (tmp_path / fact.name).read_bytes() == b"original"


def test_aggregate_retention_counts_all_kinds_without_refund(tmp_path):
    tmp_path.chmod(0o700)
    with ArtifactStore(tmp_path, limits=InventoryLimits(diagnostic_job_bytes=7), check=lambda: None) as store:
        store.put("inventory.json", b"1234")
        store.put("sbom.cdx.json", b"567")
        with pytest.raises(InputRefusal, match="artifact-retention-budget-exceeded"):
            store.put("grype.json", b"8")
        assert store.reserved_bytes == 7 and len(store.facts) == 2
        with pytest.raises(InputRefusal, match="artifact-retention-budget-exceeded"):
            store.put("grype.json", b"")


def test_failed_write_reservation_and_partial_evidence_are_retained(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    original = os.write
    calls = 0

    def failing_write(fd, raw):
        nonlocal calls
        calls += 1
        if calls == 1:
            return original(fd, raw[:2])
        raise OSError("private diagnostic must not escape")

    with ArtifactStore(tmp_path, limits=InventoryLimits(), check=lambda: None) as store:
        monkeypatch.setattr(os, "write", failing_write)
        with pytest.raises(InputRefusal, match="^artifact-write-failed$"):
            store.put("inventory.json", b"12345")
        assert store.reserved_bytes == 5 and not store.facts
        assert (tmp_path / "inventory.json").read_bytes() == b"12"


@pytest.mark.parametrize("change", ["replace", "symlink", "hardlink", "chmod", "rewrite"])
def test_artifact_mutations_refuse_later_admission(tmp_path, change):
    tmp_path.chmod(0o700)
    with ArtifactStore(tmp_path, limits=InventoryLimits(), check=lambda: None) as store:
        store.put("inventory.json", b"123")
        path = tmp_path / "inventory.json"
        if change == "replace":
            path.unlink()
            path.write_bytes(b"123")
        elif change == "symlink":
            path.unlink()
            path.symlink_to("absent")
        elif change == "hardlink":
            os.link(path, tmp_path / "alias")
        elif change == "chmod":
            path.chmod(0o644)
        else:
            path.write_bytes(b"456")
        with pytest.raises(InputRefusal, match="changed-artifact|unexpected-artifact"):
            store.validate()


def test_held_directory_replacement_is_refused(tmp_path):
    root = tmp_path / "output"
    root.mkdir(mode=0o700)
    with ArtifactStore(root, limits=InventoryLimits(), check=lambda: None) as store:
        root.rename(tmp_path / "moved")
        root.mkdir(mode=0o700)
        with pytest.raises(InputRefusal, match="changed-artifact-root"):
            store.put("inventory.json", b"data")
        assert not list(root.iterdir())


def test_directory_sync_failure_does_not_admit_new_artifact(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    original = os.fsync
    with ArtifactStore(tmp_path, limits=InventoryLimits(), check=lambda: None) as store:

        def sync(fd):
            if fd == store.fd:
                raise OSError("uncertain directory sync")
            return original(fd)

        monkeypatch.setattr(os, "fsync", sync)
        with pytest.raises(InputRefusal, match="artifact-write-failed"):
            store.put("inventory.json", b"available")
        assert not store.facts and (tmp_path / "inventory.json").read_bytes() == b"available"


def test_output_store_cannot_use_another_ledger(tmp_path):
    root, output = roots(tmp_path)
    config = DiscoveryConfig()
    with Source(root) as source:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        with ArtifactStore(output, limits=InventoryLimits(), check=lambda: None) as store:
            with pytest.raises(ValueError, match="artifact-store-ledger-mismatch"):
                run(source, budget, config, store)


def test_control_record_reservation_precedes_any_analysis(tmp_path):
    root, output = roots(tmp_path)
    (root / "requirements.in").write_text("pip==26.0.1\n")
    config = DiscoveryConfig()
    with Source(root) as source:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        with ArtifactStore(output, limits=InventoryLimits(diagnostic_job_bytes=65535), check=budget.check) as store:
            with pytest.raises(InputRefusal, match="artifact-retention-budget-exceeded"):
                run(source, budget, config, store)
            assert not source.cache and not store.facts and not list(output.iterdir())


def test_interrupted_write_keeps_partial_bytes_and_permanently_refuses_reuse(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    original = os.write

    def interrupted(fd, raw):
        original(fd, raw[:2])
        raise KeyboardInterrupt()

    with ArtifactStore(tmp_path, limits=InventoryLimits(), check=lambda: None) as store:
        monkeypatch.setattr(os, "write", interrupted)
        with pytest.raises(KeyboardInterrupt):
            store.put("inventory.json", b"1234")
        assert not store.facts and store.reserved_bytes == 4
        assert (tmp_path / "inventory.json").read_bytes() == b"12"
        with pytest.raises(InputRefusal, match="artifact-write-interrupted"):
            store.validate()


def test_same_metadata_content_rewrite_is_caught_by_held_hash(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    with ArtifactStore(tmp_path, limits=InventoryLimits(), check=lambda: None) as store:
        store.put("inventory.json", b"123")
        # Hold metadata observation constant so this proof does not depend on
        # filesystem timestamp resolution or metadata's ability to notice it.
        monkeypatch.setattr("sourcebastion.inventory.artifacts._identity", lambda info: (0,))
        store._metadata = (0,)
        descriptor, _expected, fact = store._files["inventory.json"]
        store._files["inventory.json"] = (descriptor, (0,), fact)
        (tmp_path / "inventory.json").write_bytes(b"456")
        with pytest.raises(InputRefusal, match="changed-artifact-content"):
            store.validate()


def test_source_containing_output_directory_is_refused(tmp_path):
    tmp_path.chmod(0o700)
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    config = DiscoveryConfig()
    with Source(tmp_path) as source:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        with ArtifactStore(output, limits=InventoryLimits(), check=budget.check) as store:
            with pytest.raises(InputRefusal, match="source-artifact-roots-overlap"):
                run(source, budget, config, store)


@pytest.mark.parametrize("source_alias", [False, True])
def test_descriptor_ancestry_refuses_ignored_source_output_through_aliases(tmp_path, source_alias):
    root = tmp_path / "source"
    root.mkdir()
    (root / "requirements.in").write_text("pip==26.0.1\n")
    hidden = root / ".git"
    hidden.mkdir()
    output = hidden / "output"
    output.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path, target_is_directory=True)
    visible_source = alias / "source" if source_alias else root
    visible_output = output if source_alias else alias / "source" / ".git" / "output"
    config = DiscoveryConfig()
    with Source(visible_source) as source:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        with ArtifactStore(visible_output, limits=InventoryLimits(), check=budget.check) as store:
            with pytest.raises(InputRefusal, match="source-artifact-roots-overlap"):
                run(source, budget, config, store)
            assert not list(output.iterdir()) and not source.cache and store.reserved_bytes == 0
