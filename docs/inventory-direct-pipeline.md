# Inactive direct-source pipeline

`sourcebastion.inventory.direct_pipeline.run_direct` joins static source
composition, canonical serialization, CycloneDX export and final source
validation. No customer scan route imports it. It has no consumer launcher,
release/runtime admission, kernel-resource authority or finding publication.
Matching remains `not_run`, including when composition and export finish.

The trusted caller supplies an already admitted `Source`, its admission-time
`PipelineBudget`, matching discovery policy and producer, plus an `ArtifactStore`
using that exact ledger. The store requires an existing empty owner-only output
directory outside the source root. Composition, export, retention and final
validation share the same deadline and semantic counter. No stage creates a new
allowance. Existing serialization/model internals remain bounded by their
structural caps and require the future kernel envelope; every operation is not
individually charged by the cooperative counter.

Before any reservation or analysis, bounded descriptor-relative ancestor walks
reject either held root containing the other, including symlinked ancestors of
the visible paths. Lookup/depth/budget failures refuse admission. This is mount
namespace ancestry only: the parent must independently verify that bind-mount
origins do not alias source subtrees through distinct namespace paths.

The store pins the output descriptor and writes fixed filenames exclusively,
with owner-only regular single-link files. It checks held and visible metadata,
syncs files and the held directory, and rehashes held bytes at admission and
validation to detect same-length rewrites even when metadata is unchanged.
Failed or interrupted writes retain available evidence without overwriting or
deleting it. Failed writes cannot produce artifact facts or replenish retention.
These checks cover one invocation, not persistent custody or fencing against
an administrator sharing its identity.

Filesystem retention reserves full artifact sizes before writing, across
inventory, SBOM, raw report, recovery and execution filenames. Each file is
limited to its configured maximum (at most 64MiB); all reservations together
are limited to 256MiB. The controller also reserves 64KiB before analysis for its
returned control record. Reservations are not refunded. Canonical and export
buffers are produced by existing bounded serializers before retention; this
allocator is not a process memory limiter. A refused control reservation raises
without producing a record. A failed later stage returns a bounded failure
record and preserves earlier files as available diagnostic evidence.

The versioned record binds the caller's source/producer/environment assertions,
exact retained hashes and sizes, inventory fidelity and separate invocation
outcomes. Canonical `StageStates` remain unchanged. The semantic count is a
snapshot at record preparation, not an aggregate CPU measurement or a portable
inventory identity. `finalized` means only that these child stages and final
source/output checks finished. A source or output validation failure refuses
finalization even when earlier complete bytes remain available.

The record is returned on a future parent control channel, rather than leaving
a success file before final validation. The parent must authenticate the child
result, independently own the mount and runtime/source/advisory custody, drain
every process, and reread admitted files through safe descriptors. Child facts
cannot attest these parent obligations. No reader should treat retained files
alone, an empty SBOM, or `finalized` as a successful vulnerability scan.

Next gates are the fixed consumer runner and exact recovery, host-owned
container/cgroup CPU, memory, swap, PID, wall and cancellation enforcement,
versioned runtime/advisory/execution admission, native hostile lifecycle proofs,
release packaging and negotiated platform ingestion. M044 ownership/fencing,
M045 measurements and the separately queued SBOM browser are unchanged.
