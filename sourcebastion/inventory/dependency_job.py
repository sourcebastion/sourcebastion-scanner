"""Inactive fixed-consumer job; returned child facts need parent admission.

The trusted parent must isolate this entire job, enforce its aggregate kernel
budget, own immutable mounts and drain all descendants before accepting files.
No customer route invokes this library; no child JSON establishes those facts.
"""

from contextlib import ExitStack
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import tempfile
from threading import Event

from .artifacts import ArtifactStore
from .budget import PipelineBudget
from .compose_source import compose_source
from .consumer_runtime import ADVISORIES, RuntimeBinding, RuntimeSpec
from .contract import Producer, canonical_bytes
from .cyclonedx import export
from .inputs import InputRefusal
from .matching import Consumer, recover
from .process_capture import _capture
from .provider import _decode

VERSION = "sourcebastion.dependency-job/1"


def _render(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class DependencyResult:
    receipt: bytes
    finalized: bool


def run_dependency(
    source,
    *,
    budget,
    config,
    producer,
    source_sha256,
    store,
    runtime,
    environment=None,
    go_runtime=None,
    cancelled=None,
):
    """Finalize child facts with one admission ledger and held runtime custody.

    The parent must independently admit kernel limits, immutable mounts and
    all-descendant cleanup before accepting these artifacts as a scan.
    """
    with ExitStack() as lifetime:
        return _run_dependency(
            source,
            budget=budget,
            config=config,
            producer=producer,
            source_sha256=source_sha256,
            store=store,
            runtime=runtime,
            environment=environment,
            go_runtime=go_runtime,
            cancelled=cancelled,
            lifetime=lifetime,
        )


def _run_dependency(
    source,
    *,
    budget,
    config,
    producer,
    source_sha256,
    store,
    runtime,
    environment,
    go_runtime,
    cancelled,
    lifetime,
):
    """Use one admission-time Source/ledger through actual matching and recovery.

    Only trusted controller code supplies runtime preparation facts and source
    identity. Canonical bytes/stages stay immutable when later matching fails.
    Receipt success means finalized child facts, never parent scan acceptance.
    The caller creates the ledger at job admission; this function cannot reset
    its deadline, semantic allowance or artifact reservations.
    """
    if type(budget) is not PipelineBudget or type(store) is not ArtifactStore or store.check != budget.check:
        raise TypeError("controller-budget-and-store-required")
    budget.bind(source, config)
    if type(runtime) is not RuntimeSpec or (cancelled is not None and type(cancelled) is not Event):
        raise TypeError("controller-runtime-and-cancellation-required")
    if store._names or store.reserved_bytes:
        raise ValueError("fresh-artifact-store-required")
    if type(source_sha256) is not str or re.fullmatch(r"[a-f0-9]{64}", source_sha256) is None:
        raise ValueError("invalid-controller-source-digest")
    producer = Producer.model_validate(producer)
    store.require_source_separation(source)
    store.reserve_control()

    def tick():
        budget.check()
        if cancelled is not None and cancelled.is_set():
            store._refusal = store._refusal or "dependency-job-cancelled"
            raise InputRefusal("dependency-job-cancelled")

    stages = {
        key: "not_run"
        for key in (
            "runtime_admission",
            "composition",
            "inventory",
            "export",
            "consumer_execution",
            "recovery",
            "finalization",
        )
    }
    stage, reason = "runtime_admission", None
    inventory_state = environment_sha = consumer_fact = recovery_identity = execution = None
    try:
        tick()
        binding = lifetime.enter_context(RuntimeBinding(runtime, check=tick))
        with tempfile.TemporaryDirectory(prefix="dependency-consumer-") as temporary:
            private = Path(temporary)
            for name in ("cwd", "home", "config-home"):
                (private / name).mkdir(mode=0o700)
            raw_config = (
                "check-for-app-update: false\ndb:\n  auto-update: false\n  cache-dir: "
                + json.dumps(str(ADVISORIES))
                + "\n  validate-age: true\n  max-allowed-built-age: 120h\n  validate-by-hash-on-start: true\n"
            ).encode()
            store.put("grype.yaml", raw_config)
            consumer_environment = {
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "HOME": str(private / "home"),
                "XDG_CONFIG_HOME": str(private / "config-home"),
                "LC_ALL": "C",
                "GRYPE_DB_CACHE_DIR": str(ADVISORIES),
                "GRYPE_DB_AUTO_UPDATE": "false",
                "GRYPE_CHECK_FOR_APP_UPDATE": "false",
                "GRYPE_DB_VALIDATE_AGE": "true",
                "GRYPE_DB_MAX_ALLOWED_BUILT_AGE": "120h",
                "GRYPE_DB_VALIDATE_BY_HASH_ON_START": "true",
            }
            configuration = {
                "yaml_sha256": _sha(raw_config),
                "environment": consumer_environment,
                "source_policy": "explicit-sbom-only",
            }
            prefix = [f"/proc/self/fd/{binding.binary}", "--config", str(store.root / "grype.yaml")]

            def invoke(args, *, name, maximum):
                tick()
                binding._metadata()
                result = _capture(
                    prefix + args,
                    source=source,
                    config=config,
                    budget=budget,
                    store=store,
                    environment=consumer_environment,
                    cwd=private / "cwd",
                    cancelled=cancelled,
                    stdout_name=name + ".json",
                    stderr_name=name + ".stderr",
                    stdout_maximum=maximum,
                    stderr_maximum=min(65536, store.limits.diagnostic_file_bytes),
                    pass_fds=(binding.binary,),
                )
                tick()
                return result

            documents = {}
            for name, args in (("version", ["version", "-o", "json"]), ("status", ["db", "status", "-o", "json"])):
                observed = invoke(args, name="grype-" + name, maximum=min(65536, store.limits.diagnostic_file_bytes))
                if observed.returncode != 0:
                    raise InputRefusal("dependency-consumer-nonzero-exit")
                documents[name] = _decode(store.read("grype-" + name + ".json"), tick)
            version, status = documents["version"], documents["status"]
            snapshot = _decode(binding.read_snapshot(), tick)
            if (
                version.get("version") != runtime.version
                or status.get("valid") is not True
                or status.get("schemaVersion") != runtime.advisory_schema
                or status.get("built") != runtime.advisory_built
                or status.get("path") != str(ADVISORIES / "6/vulnerability.db")
                or type(snapshot.get("database")) is not dict
                or snapshot["database"].get("valid") is not True
                or any(snapshot["database"].get(key) != status.get(key) for key in ("built", "schemaVersion"))
            ):
                raise InputRefusal("dependency-consumer-status-mismatch")
            consumer = Consumer(
                binary_sha256=runtime.binary_sha256,
                version=runtime.version,
                config_sha256=_sha(_render(configuration)),
                advisory_snapshot_sha256=runtime.advisory_sha256,
                advisory_schema=runtime.advisory_schema,
                advisory_built=runtime.advisory_built,
            )
            consumer_fact = consumer.model_dump(mode="json")
            stages[stage] = "succeeded"
            stage = "composition"
            value = compose_source(
                source,
                source_sha256=source_sha256,
                producer=producer,
                config=config,
                environment=environment,
                limits=store.limits,
                go_runtime=go_runtime,
                budget=budget,
            )
            inventory_state, environment_sha = value.stages.inventory, value.environment_sha256
            stages[stage] = "succeeded"
            stage = "inventory"
            tick()
            canonical = canonical_bytes(value)
            tick()
            store.put("inventory.json", canonical)
            stages[stage] = "succeeded"
            stage = "export"
            artifact = export(value, deadline=budget.deadline, check=tick)
            store.put("sbom.cdx.json", artifact.content)
            stages[stage] = "succeeded"
            stage = "consumer_execution"
            captured = invoke(
                ["sbom:" + str(store.root / "sbom.cdx.json"), "-o", "json", "-q"],
                name="grype",
                maximum=store.limits.diagnostic_file_bytes,
            )
            execution = {"exit_code": captured.returncode, "lifecycle": captured.lifecycle}
            if captured.returncode != 0:
                raise InputRefusal("dependency-consumer-nonzero-exit")
            stages[stage] = "succeeded"
            stage = "recovery"
            raw = store.read("grype.json")
            report = _decode(raw, tick)
            descriptor = report.get("descriptor")
            database = descriptor.get("db") if type(descriptor) is dict else None
            analysis_status = database.get("status") if type(database) is dict else None
            if type(analysis_status) is not dict or analysis_status.get("path") != str(
                ADVISORIES / "6/vulnerability.db"
            ):
                raise InputRefusal("dependency-consumer-database-path-mismatch")
            result = recover(value, artifact, raw, consumer=consumer, deadline=budget.deadline, check=tick)
            recovery_identity = result.identity_sha256
            recovered = {
                "schema_version": "sourcebastion.dependency-recovery/1",
                "identity_sha256": result.identity_sha256,
                "inventory_sha256": result.inventory_sha256,
                "sbom_sha256": result.sbom_sha256,
                "output_sha256": result.output_sha256,
                "matches": [asdict(row) for row in result.matches],
                "occurrence_contexts": {
                    identifier: json.loads(context) for identifier, context in result.occurrence_contexts
                },
            }
            tick()
            recovery_raw = _render(recovered)
            tick()
            store.put("recovery.json", recovery_raw)
            stages[stage] = "succeeded"
            stage = "finalization"
            tick()
            source.validate()
            store.validate()
            tick()
            if canonical_bytes(value) != canonical or store.read("sbom.cdx.json") != artifact.content:
                raise InputRefusal("changed-dependency-artifacts")
            stages[stage] = "succeeded"
    except (InputRefusal, ValueError, OSError):
        stages[stage] = "failed"
        reason = "dependency-job-stage-failed"
    receipt = {
        "schema_version": VERSION,
        "authority": "child-artifact-facts-only",
        "source_sha256": source_sha256,
        "producer": producer.model_dump(mode="json"),
        "discovery_config_sha256": config.sha256,
        "environment_sha256": environment_sha,
        "limits": store.limits.model_dump(mode="json"),
        "inventory_state": inventory_state,
        "stages": stages,
        "consumer": consumer_fact,
        "execution": execution,
        "recovery_identity_sha256": recovery_identity,
        "kernel_admission": "not_observed",
        "reason": reason,
        "semantic_checks": {"consumed_at_receipt_preparation": budget.consumed, "maximum": budget.maximum},
        "retention_reserved_bytes": store.reserved_bytes,
        "artifacts": [asdict(row) for row in store.facts],
    }
    raw_receipt = _render(receipt)
    if len(raw_receipt) > 65536:
        raise InputRefusal("dependency-control-record-budget-exceeded")
    if reason is None:
        try:
            tick()
            binding.validate()
            source.validate()
            store.validate()
            binding._metadata()
            tick()
        except (InputRefusal, ValueError, OSError):
            stages["finalization"] = "failed"
            receipt["reason"] = "dependency-job-finalization-failed"
            return DependencyResult(_render(receipt), False)
    return DependencyResult(raw_receipt, reason is None)
