"""Exclusive retention, shared-budget refusal and immutable artifact stages."""

import hashlib
import json
import os
import re

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


def _report(value):
    """A controller-admitted Grype report for this inventory's occurrences."""
    from tests.test_inventory_matching import report

    return json.dumps(report(value.occurrences), indent=2).encode()


def _matching_consumer():
    from tests.test_inventory_matching import consumer

    return consumer()


def test_matching_charges_the_same_ledger_as_composition_and_export(tmp_path):
    """One semantic counter across every stage, not one per stage."""
    from sourcebastion.inventory.contract import Inventory

    root, output = roots(tmp_path)
    (root / "requirements.in").write_text("pip==26.0.1\n")
    config = DiscoveryConfig()
    with Source(root) as source:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        with ArtifactStore(output, limits=InventoryLimits(), check=budget.check) as store:
            without = run(source, budget, config, store)
    baseline = json.loads(without.receipt)["semantic_checks"][
        "consumed_at_receipt_preparation"
    ]
    composed = Inventory.model_validate_json((output / "inventory.json").read_bytes())

    second = tmp_path / "second"
    second.mkdir()
    root, output = roots(second)
    (root / "requirements.in").write_text("pip==26.0.1\n")
    with Source(root) as source:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        with ArtifactStore(output, limits=InventoryLimits(), check=budget.check) as store:
            result = run_direct(
                source,
                budget=budget,
                config=config,
                producer=producer(config),
                source_sha256="b" * 64,
                store=store,
                consumer=_matching_consumer(),
                report=_report(composed),
            )

    receipt = json.loads(result.receipt)
    assert receipt["matching"] == "succeeded"
    assert receipt["semantic_checks"]["consumed_at_receipt_preparation"] > baseline


def test_a_matcher_that_refuses_leaves_the_inventory_and_sbom_intact(tmp_path):
    """S04 keeps the two statuses apart: a valid inventory survives a failed
    match, because the scan did record what it found."""
    root, output = roots(tmp_path)
    (root / "requirements.in").write_text("pip==26.0.1\n")
    config = DiscoveryConfig()
    with Source(root) as source:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        with ArtifactStore(output, limits=InventoryLimits(), check=budget.check) as store:
            result = run_direct(
                source,
                budget=budget,
                config=config,
                producer=producer(config),
                source_sha256="b" * 64,
                store=store,
                consumer=_matching_consumer(),
                report=b'{"matches": [], "source": {"type": "sbom-file"}',
            )

    receipt = json.loads(result.receipt)
    assert receipt["matching"] == "failed"
    assert receipt["reason"] is None and result.finalized
    assert receipt["stages"]["export"] == "succeeded"
    names = {fact["name"] for fact in receipt["artifacts"]}
    assert {"inventory.json", "sbom.cdx.json"} <= names
    assert "grype.json" not in names


def test_a_consumer_without_a_report_is_refused(tmp_path):
    root, output = roots(tmp_path)
    (root / "requirements.in").write_text("pip==26.0.1\n")
    config = DiscoveryConfig()
    with Source(root) as source:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        with ArtifactStore(output, limits=InventoryLimits(), check=budget.check) as store:
            with pytest.raises(ValueError, match="supplied-together"):
                run_direct(
                    source,
                    budget=budget,
                    config=config,
                    producer=producer(config),
                    source_sha256="b" * 64,
                    store=store,
                    consumer=_matching_consumer(),
                )


def _matched(tmp_path, *, report=None, consumer=None, requirements="pip==26.0.1\n"):
    """Run the pipeline twice: once to compose, once with a real report."""
    from sourcebastion.inventory.contract import Inventory

    root, output = roots(tmp_path)
    (root / "requirements.in").write_text(requirements)
    config = DiscoveryConfig()
    with Source(root) as source:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        with ArtifactStore(output, limits=InventoryLimits(), check=budget.check) as store:
            run(source, budget, config, store)
    composed = Inventory.model_validate_json((output / "inventory.json").read_bytes())

    raw = _report(composed) if report is None else report
    second = tmp_path / "matched"
    second.mkdir()
    root, output = roots(second)
    (root / "requirements.in").write_text(requirements)
    with Source(root) as source:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        with ArtifactStore(output, limits=InventoryLimits(), check=budget.check) as store:
            result = run_direct(
                source,
                budget=budget,
                config=config,
                producer=producer(config),
                source_sha256="b" * 64,
                store=store,
                consumer=_matching_consumer() if consumer is None else consumer,
                report=raw,
            )
    return json.loads(result.receipt), composed, raw


def test_result_provenance_names_the_advisory_snapshot_the_findings_came_from(tmp_path):
    """S04 asks for engine/config/registry identity in result provenance
    together with the advisory snapshot. The producer carried the first three;
    without the consumer, a reuse decision is made against unknown advisories."""
    receipt, _composed, raw = _matched(tmp_path)
    expected = _matching_consumer().model_dump(mode="json")

    assert receipt["matching"] == "succeeded"
    identity = receipt["matching_identity"]
    assert identity["consumer"] == expected
    for field in ("advisory_snapshot_sha256", "advisory_schema", "advisory_built"):
        assert identity["consumer"][field] == expected[field], field
    assert re.fullmatch(r"[0-9a-f]{64}", identity["identity_sha256"])
    assert identity["matches"] == len(json.loads(raw)["matches"])
    assert identity["matches"] > 0, "a report with no matches proves nothing here"


def test_the_matching_identity_binds_the_inventory_the_sbom_and_the_output(tmp_path):
    """`recover`'s joint digest, so none of the four can be swapped under the
    others: equal inputs agree, and a different inventory does not."""
    again = tmp_path / "again"
    again.mkdir()
    first, _composed, _raw = _matched(tmp_path)
    second, _composed, _raw = _matched(again)

    assert (
        first["matching_identity"]["identity_sha256"]
        == second["matching_identity"]["identity_sha256"]
    )

    other = tmp_path / "other"
    other.mkdir()
    changed, _composed, _raw = _matched(other, requirements="pip==26.0.1\npackaging==26.3\n")

    assert changed["matching"] == "succeeded"
    assert (
        changed["matching_identity"]["identity_sha256"]
        != first["matching_identity"]["identity_sha256"]
    ), "a different inventory must not reuse the same matching identity"


def test_a_consumer_contradicting_the_report_matches_nothing(tmp_path):
    """The snapshot is asserted by the controller and checked against the
    report. A mismatch is a failed match, not a match under a wrong snapshot."""
    drifted = dict(_matching_consumer(), advisory_built="2020-01-01T00:00:00Z")
    receipt, _composed, _raw = _matched(tmp_path, consumer=drifted)

    assert receipt["matching"] == "failed"
    assert receipt["matching_identity"] is None
    assert receipt["reason"] is None and receipt["stages"]["export"] == "succeeded"


def test_the_artifact_facts_already_carry_the_three_artifact_digests(tmp_path):
    """The identity does not repeat them: the receipt would say the same thing
    twice, and two copies can disagree."""
    receipt, _composed, _raw = _matched(tmp_path)

    facts = {fact["name"]: fact["sha256"] for fact in receipt["artifacts"]}
    assert {"inventory.json", "sbom.cdx.json", "grype.json"} <= set(facts)
    assert all(re.fullmatch(r"[0-9a-f]{64}", digest) for digest in facts.values())
    assert not set(receipt["matching_identity"]) & {
        "inventory_sha256",
        "sbom_sha256",
        "output_sha256",
    }


def test_a_failed_match_records_no_advisory_provenance(tmp_path):
    """The consumer is a controller assertion. Recording it after a failure
    would read as provenance for advisories never established against this
    inventory."""
    receipt, _composed, _raw = _matched(
        tmp_path, report=b'{"matches": [], "source": {"type": "sbom-file"}'
    )

    assert receipt["matching"] == "failed"
    assert receipt["matching_identity"] is None


def test_a_pipeline_without_a_matcher_claims_no_advisory_provenance(tmp_path):
    root, output = roots(tmp_path)
    (root / "requirements.in").write_text("pip==26.0.1\n")
    config = DiscoveryConfig()
    with Source(root) as source:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        with ArtifactStore(output, limits=InventoryLimits(), check=budget.check) as store:
            result = run(source, budget, config, store)

    receipt = json.loads(result.receipt)
    assert receipt["matching"] == "not_run"
    assert receipt["matching_identity"] is None
