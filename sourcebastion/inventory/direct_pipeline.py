"""Inactive direct-source composition/export controller, before host admission.

No customer route invokes this module. It does not execute a consumer, attest
kernel limits or publish findings. The parent must still independently admit
runtime/source custody, enforce the resource envelope and own cleanup.
"""

from dataclasses import asdict, dataclass
import json
import re

from .artifacts import ArtifactStore
from .budget import PipelineBudget
from .compose_source import compose_source
from .contract import Producer, canonical_bytes
from .cyclonedx import export
from .inputs import InputRefusal
from .matching import recover

VERSION = "sourcebastion.direct-pipeline/1"


@dataclass(frozen=True)
class DirectResult:
    """Child artifact facts only; never a successful vulnerability scan."""

    receipt: bytes
    finalized: bool


def run_direct(
    source,
    *,
    budget,
    config,
    producer,
    source_sha256,
    store,
    environment=None,
    go_runtime=None,
    consumer=None,
    report=None,
):
    """Compose, freeze and export using the caller's admission-time ledger.

    Every invocation is single-use through the exclusive store. A failed stage
    leaves earlier complete artifacts intact. Exhaustion never receives extra
    time/work to publish a success receipt; the returned bounded failure record
    lets an outer controller report failure. Its 64KiB reservation precedes
    analysis; a refused reservation raises without allocating a control record.

    `consumer` and `report` are supplied together by a controller that has
    already executed Grype against the exported SBOM; this module never runs a
    consumer. Recovery then charges the same ledger as composition and export,
    so one semantic counter spans the stages rather than each stage keeping its
    own. Matching failure is recorded and does not fail the pipeline: a scan
    that produced a valid inventory still has one when the matcher does not
    answer, which is the separation this slice exists to keep.
    """
    if type(budget) is not PipelineBudget or type(store) is not ArtifactStore:
        raise TypeError("controller-budget-and-artifact-store-required")
    budget.bind(source, config)
    if store.check != budget.check:
        raise ValueError("artifact-store-ledger-mismatch")
    if store.facts or store.reserved_bytes:
        raise ValueError("fresh-artifact-store-required")
    store.require_source_separation(source)
    if type(source_sha256) is not str or not re.fullmatch(r"[a-f0-9]{64}", source_sha256):
        raise ValueError("invalid-controller-source-digest")
    producer = Producer.model_validate(producer)
    if (consumer is None) != (report is None):
        raise ValueError("matching-consumer-and-report-are-supplied-together")
    store.reserve_control()
    stages = {key: "not_run" for key in ("composition", "inventory", "export", "source_validation", "finalization")}
    reason, inventory_state, environment_sha = None, None, None
    matching_state, artifact, value = "not_run", None, None
    stage = "composition"
    try:
        budget.check()
        value = compose_source(
            source,
            source_sha256=source_sha256,
            producer=producer,
            environment=environment,
            config=config,
            limits=store.limits,
            go_runtime=go_runtime,
            budget=budget,
        )
        stages[stage] = "succeeded"
        inventory_state, environment_sha = value.stages.inventory, value.environment_sha256
        stage = "inventory"
        budget.check()
        raw = canonical_bytes(value)
        budget.check()
        store.put("inventory.json", raw)
        stages[stage] = "succeeded"
        stage = "export"
        artifact = export(value, deadline=budget.deadline, check=budget.check)
        store.put("sbom.cdx.json", artifact.content)
        stages[stage] = "succeeded"
        stage = "source_validation"
        budget.check()
        source.validate()
        budget.check()
        store.validate()
        stages[stage] = "succeeded"
        stage = "finalization"
        budget.check()
    except (InputRefusal, ValueError, OSError):
        # No exception text, local path or customer content becomes public.
        stages[stage] = "failed"
        reason = "direct-pipeline-stage-failed"
    if reason is None and report is not None:
        # Its own boundary on purpose. A matcher that refuses, times out or
        # returns a report this inventory cannot account for leaves the
        # composed inventory and the exported SBOM exactly as they are: the
        # pipeline recorded what it found, and says separately that nothing
        # was matched against it. Charging the shared ledger keeps one
        # semantic counter across every stage.
        try:
            recovery = recover(
                value,
                artifact,
                report,
                consumer=consumer,
                deadline=budget.deadline,
                check=budget.check,
            )
            # The store already reserves a slot for the consumer's report.
            store.put("grype.json", recovery.original_output)
            matching_state = recovery.matching
        except (InputRefusal, ValueError, OSError):
            matching_state = "failed"
    receipt = {
        "schema_version": VERSION,
        "authority": "child-artifact-facts-only",
        "source_sha256": source_sha256,
        "producer": producer.model_dump(mode="json"),
        "limits": store.limits.model_dump(mode="json"),
        "environment_sha256": environment_sha,
        "inventory_state": inventory_state,
        "stages": stages,
        "matching": matching_state,
        "kernel_admission": "not_observed",
        "reason": reason,
        "semantic_checks": {"consumed_at_receipt_preparation": budget.consumed, "maximum": budget.maximum},
        "retention_reserved_bytes": store.reserved_bytes,
        "artifacts": [asdict(fact) for fact in store.facts],
    }
    if reason is None:
        stages["finalization"] = "succeeded"
    raw_receipt = _render(receipt)
    if reason is None:
        try:
            # The parent receives this small record on its control channel;
            # no success file is left behind before these last source checks.
            budget.check()
            source.validate()
            store.validate()
        except (InputRefusal, ValueError, OSError):
            stages["finalization"] = "failed"
            receipt["reason"] = "direct-pipeline-finalization-failed"
            return DirectResult(_render(receipt), False)
    return DirectResult(raw_receipt, reason is None)


def _render(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    if len(raw) > 65536:
        raise InputRefusal("direct-control-record-budget-exceeded")
    return raw
