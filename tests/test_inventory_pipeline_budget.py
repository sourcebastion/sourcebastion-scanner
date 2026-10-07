"""One allowance spans source work, export and exact-ID matching recovery."""

import json
import time

import pytest

from sourcebastion.inventory.budget import PipelineBudget
from sourcebastion.inventory.compose_source import compose_source
from sourcebastion.inventory.contract import Producer, canonical_bytes
from sourcebastion.inventory.cyclonedx import export
from sourcebastion.inventory.discovery import discover
from sourcebastion.inventory.inputs import InputRefusal, Source
from sourcebastion.inventory.matching import recover
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256
from tests.test_inventory_matching import consumer, report


def compose(source, config, budget=None):
    producer = Producer(
        name="test-controller",
        version="1",
        code_sha256="a" * 64,
        registry_sha256=REGISTRY_SHA256,
        config_sha256=config.sha256,
    )
    return compose_source(source, source_sha256="b" * 64, producer=producer, config=config, budget=budget)


def test_stages_share_consumption_without_changing_canonical_authority(tmp_path):
    (tmp_path / "requirements.in").write_text("pip==26.0.1\n")
    config = DiscoveryConfig()
    with Source(tmp_path) as source:
        expected = canonical_bytes(compose(source, config))
    with Source(tmp_path) as source:
        budget = PipelineBudget(source, config=config, deadline=time.monotonic() + 10)
        value = compose(source, config, budget)
        after_composition = budget.consumed
        artifact = export(value, deadline=budget.deadline, check=budget.check)
        after_export = budget.consumed
        raw = json.dumps(report(value.occurrences)).encode()
        recovered = recover(value, artifact, raw, consumer=consumer(), deadline=budget.deadline, check=budget.check)
        assert 0 < after_composition < after_export < budget.consumed
        assert recovered.original_output == raw and len(recovered.matches) == 1
        assert canonical_bytes(value) == expected
        assert value.stages.export == value.stages.matching == "not-run"


def test_export_cannot_replenish_allowance_used_by_composition(tmp_path):
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    config = DiscoveryConfig()
    with Source(tmp_path) as source:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        value = compose(source, config, budget)
        before = canonical_bytes(value)
        budget.step(budget.maximum - budget.consumed)
        with pytest.raises(InputRefusal, match="pipeline-semantic-budget-exceeded"):
            export(value, deadline=budget.deadline, check=budget.check)
        assert canonical_bytes(value) == before and value.stages.export == "not-run"
        consumed = budget.consumed
        for operation in (budget.check, budget.guard):
            with pytest.raises(InputRefusal, match="pipeline-semantic-budget-exceeded"):
                operation()
        assert budget.consumed == consumed


def test_recovery_exhaustion_preserves_inventory_export_and_original_report(tmp_path):
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    config = DiscoveryConfig()
    with Source(tmp_path) as source:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        value = compose(source, config, budget)
        before = canonical_bytes(value)
        artifact = export(value, deadline=budget.deadline, check=budget.check)
        raw = json.dumps(report(value.occurrences)).encode()
        budget.step(budget.maximum - budget.consumed)
        with pytest.raises(InputRefusal, match="pipeline-semantic-budget-exceeded"):
            recover(value, artifact, raw, consumer=consumer(), deadline=budget.deadline, check=budget.check)
        assert canonical_bytes(value) == before and artifact.content
        assert json.loads(raw)["matches"][0]["artifact"]["id"] == value.occurrences[0].id


def test_discovery_references_and_prior_work_share_one_allowance(tmp_path):
    (tmp_path / "requirements.txt").write_text("-r child.in\n")
    (tmp_path / "child.in").write_text("pip==26.0.1\n")
    config = DiscoveryConfig(semantic_checks=2)
    with Source(tmp_path) as source:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        budget.step(2)
        result = discover(source, config=config, budget=budget)
        assert result.semantic_checks == 1
        assert "pipeline-semantic-budget-exceeded" in result.refusal_codes
        assert budget.consumed == 3
        with pytest.raises(InputRefusal, match="pipeline-semantic-budget-exceeded"):
            compose(source, config, budget)


def test_composition_refuses_previously_consumed_budget_without_reset(tmp_path):
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    config = DiscoveryConfig(semantic_checks=10)
    with Source(tmp_path) as source:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        budget.step(10)
        value = compose(source, config, budget)
        assert value.stages.inventory == "failed" and not value.occurrences
        assert "pipeline-semantic-budget-exceeded" in value.coverage.refusal_codes


def test_discovery_work_is_counted_once_then_repeated_calls_still_charge(tmp_path):
    (tmp_path / "requirements.txt").write_text("-r child.in\n")
    (tmp_path / "child.in").write_text("pip==26.0.1\n")
    config = DiscoveryConfig()
    with Source(tmp_path) as source:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        first = discover(source, config=config, budget=budget)
        assert budget.consumed == first.semantic_checks == 1
        second = discover(source, config=config, budget=budget)
        assert budget.consumed == first.semantic_checks + second.semantic_checks == 2
        assert compose(source, config, budget).stages.inventory == "complete"
        assert budget.consumed > 2


def test_outer_deadline_clamps_parsers_and_cannot_be_extended(tmp_path, monkeypatch):
    with Source(tmp_path) as source:
        deadline = time.monotonic() + 5
        budget = PipelineBudget(source, config=DiscoveryConfig(), deadline=deadline)
        assert source.deadline == budget.deadline == deadline
        source.deadline += 50
        budget.guard()
        assert source.deadline == budget.deadline == deadline
        monkeypatch.setattr("sourcebastion.inventory.budget.time.monotonic", lambda: deadline + 1)
        with pytest.raises(InputRefusal, match="pipeline-deadline-exceeded"):
            budget.check()
        monkeypatch.setattr("sourcebastion.inventory.budget.time.monotonic", lambda: deadline - 1)
        with pytest.raises(InputRefusal, match="pipeline-deadline-exceeded"):
            budget.guard()


def test_source_deadline_can_only_shorten_and_admission_cannot_buy_more_time(tmp_path):
    with Source(tmp_path) as source:
        original = source.deadline
        budget = PipelineBudget(source, config=DiscoveryConfig(), deadline=original + 1000)
        assert budget.deadline == original
        source.deadline -= 1
        budget.guard()
        assert budget.deadline == original - 1


def test_epoch_failure_is_sticky_even_if_original_source_path_returns(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    with Source(root) as source:
        budget = PipelineBudget(source, config=DiscoveryConfig(), deadline=source.deadline)
        moved = tmp_path / "moved"
        root.rename(moved)
        root.mkdir()
        with pytest.raises(InputRefusal, match="changed-source-root"):
            budget.check()
        root.rmdir()
        moved.rename(root)
        with pytest.raises(InputRefusal, match="changed-source-root"):
            budget.guard()


def test_budget_is_bound_to_exact_source_and_discovery_policy(tmp_path):
    config = DiscoveryConfig()
    with Source(tmp_path) as source, Source(tmp_path) as other:
        budget = PipelineBudget(source, config=config, deadline=source.deadline)
        with pytest.raises(ValueError, match="pipeline-budget-binding-mismatch"):
            discover(other, config=config, budget=budget)
        with pytest.raises(ValueError, match="pipeline-budget-binding-mismatch"):
            compose(source, DiscoveryConfig(ignored=("ignored",)), budget)
        budget.bind(source, config)
        assert budget.consumed == 0


@pytest.mark.parametrize("deadline", [True, None, "150", float("nan"), float("inf"), -float("inf")])
def test_invalid_absolute_deadlines_refuse(tmp_path, deadline):
    with Source(tmp_path) as source:
        with pytest.raises(ValueError, match="invalid-pipeline-deadline"):
            PipelineBudget(source, config=DiscoveryConfig(), deadline=deadline)


@pytest.mark.parametrize("charge", [True, False, -1, 1.5, "1", None])
def test_invalid_semantic_charges_refuse_without_consumption(tmp_path, charge):
    with Source(tmp_path) as source:
        budget = PipelineBudget(source, config=DiscoveryConfig(), deadline=source.deadline)
        with pytest.raises(ValueError, match="invalid-pipeline-semantic-charge"):
            budget.step(charge)
        assert budget.consumed == 0


def test_zero_work_guard_and_large_projected_work_remain_bounded(tmp_path):
    with Source(tmp_path) as source:
        budget = PipelineBudget(source, config=DiscoveryConfig(), deadline=source.deadline)
        budget.step(0)
        assert budget.consumed == 0
        with pytest.raises(InputRefusal, match="pipeline-semantic-budget-exceeded"):
            budget.step(10000000)


def test_caller_dictionary_cannot_supply_budget_authority(tmp_path):
    with Source(tmp_path) as source:
        with pytest.raises(TypeError, match="controller-pipeline-budget-required"):
            compose(source, DiscoveryConfig(), {"semantic_checks": 5000000})
