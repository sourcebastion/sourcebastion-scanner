# Shared dependency pipeline bookkeeping

`PipelineBudget` is an inactive controller primitive. Discovery and composition
accept an optional controller-created ledger. Export, restricted-provider
admission and exact-ID matching recovery already accept a `check` callback; use
the same ledger's `check` there. Each callback consumes one semantic check.
Existing adapter bulk charges consume the same allowance, including zero-work
guards and projected work that exceeds the remaining allowance. Catching an
exhaustion exception does not reset the ledger.

Create the ledger at dependency-job admission with the absolute job deadline,
clamped to the earlier outer deadline. Never compute a new relative allowance
for a later stage. The ledger also shortens the bound `Source.deadline`, so
parsers using that deadline directly receive the remaining job allowance.
Source deadlines may subsequently shorten the ledger; extending Source cannot
extend the ledger. Admission and subsequent validation consume the same wall
interval. Canonical limits remain maximum policy bounds, rather than a receipt
of the actual remaining deadline or observed resources.

The ledger binds one exact `Source` object and the complete `DiscoveryConfig`
digest. Discovery reference checks and composition checks are charged once at
their original work sites. `Discovery.semantic_checks` still reports that
discovery invocation's reference visits; it is not the remaining pipeline
allowance. Repeating discovery or composition continues to consume the same
ledger. Traversal and parsed bytes remain cumulatively bounded by Source, and
existing per-artifact structural/output limits remain in their owning modules.
Serialization and typed/schema validation do not charge every internal
operation to this semantic counter; their existing structure/byte guards and
the future host kernel/time boundary remain necessary. This ledger is not a
complete aggregate record/output-retention allocator.

```python
budget = PipelineBudget(source, config=config, deadline=job_deadline)
inventory = compose_source(
    source, source_sha256=source_sha256, producer=producer,
    config=config, budget=budget,
)
artifact = export(inventory, deadline=budget.deadline, check=budget.check)
recovery = recover(
    inventory, artifact, original_report, consumer=consumer,
    deadline=budget.deadline, check=budget.check,
)
```

The example omits controller admission, Grype execution, output custody and
failure handling. Matching recovery requires separately admitted complete Grype
execution. A successful callback proves no CPU, memory, PID, advisory or process
isolation. Source epoch/deadline failures observed by the ledger poison it; its
guard checks the Source root, while Source's existing reads and final validation
still check individual inputs. A future controller must retain those checks.
Canonical inventory and export bytes survive later export/recovery failures;
their stage fields are not changed to claim later execution succeeded.

The installed native expectation driver uses one ledger per fixture Source
across both compositions and final validation. It retains consumption
checkpoints and the discovery-config digest, and compares the unchanged
source-authored semantic oracle. Raw monotonic deadlines are process-local and
are not serialized as portable identity or cross-architecture equality proof.
Test preparation and runtime hydration are outside that per-fixture interval;
the driver does not establish whole production-job resource accounting.

Existing callers without a ledger retain their existing local limits and
behavior. No customer route is enabled. This change does not install provider
executables, promote provider output into canonical records, enforce the
120-second aggregate cgroup CPU budget, provide a kernel resource envelope,
or complete M046 S04. A dedicated host-owned dependency container and parent
resource/lifecycle evidence are still required before customer activation.
