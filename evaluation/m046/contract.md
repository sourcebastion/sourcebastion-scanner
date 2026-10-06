# M046 S01 contract and budget proposal

Status: draft for independent review; no engine selected and no numerical budget
approved/frozen. The proposal does not change current runtime timeout settings.
Canonical scope: scanner [#88](https://github.com/sourcebastion/sourcebastion-scanner/issues/88),
S01 [#89](https://github.com/sourcebastion/sourcebastion-scanner/issues/89).

## Inventory and coverage v1

The production adapter must return a versioned envelope with independent
`inventory_status`, `sbom_status` and `matching_status`. Each status is one of
`complete`, `partial`, `failed`, `not-run`. An empty vulnerability list proves
none of the other statuses. Coverage has separate discovery, parsing, enumeration,
version selection, graph and environment fidelity axes. Parsing all selected
inputs does not establish a complete resolved graph. A flat requirements file
can have complete declared-pin enumeration and an explicitly unknown graph.

Each discovered input has a repository-relative path, content SHA256, format and
parser/registry version, root identity, disposition (`parsed`, `declaration-only`,
`ignored`, `unsupported`, `malformed`, `unsafe`, `budget-exceeded`) and stable
reason code. Include/constraint relationships retain origin, target and line;
cycles/escapes and unresolved replacements are explicit. A filename alone never
establishes a format. Unknown files must be counted separately from files which
are positively identified and intentionally ignored. Discovery exclusions are
recorded, not reported as parser success.

A package has a stable ecosystem/name/version identity and one or more source
occurrences. Occurrences retain root, scope, exact-version evidence, declaration
range, extras, marker and source location. An exact pin is a declared selection,
not evidence that a package was installed. PEP 503 normalization applies to PyPI,
not every ecosystem. Different versions and roots remain distinct occurrences.
Range-only declarations have no selected version and are not sent to Grype as
installed versions. Constraints do not independently create packages. An exact
constraint may intersect a required package's range; contradictions are errors.

Package-to-package edges require evidence from a supported lock or static
manifest. Includes, file ownership, project containment and scope membership
are different relationship kinds. Flat requirements cannot justify transitive
edges. Root components and external dependencies are distinguishable; comparison
reports must not hide first-party extras by filtering against their oracle.

The SBOM serializer initially targets CycloneDX 1.6 with a pinned schema; validation
must check schema and referential integrity. Any chosen engine unable to produce
the contract needs an explicitly measured adapter. Grype reads the local SBOM
and a verified offline database snapshot. Existing finding identities/locations
and M036 cache invalidation are separate acceptance tests. Cache identity includes
contract, engine, registry, parser configuration and environment-policy versions.

## Environment v1

Default hosted inventory is local and offline: no forge API, dependency install,
source/build-hook execution, metadata network resolution or submission. Customer
configuration cannot enable these. Source is read-only; scratch/output/cache are
outside the source and bounded. The production isolation boundary must restrict
host reads and sockets as well as network and writes.

Marker evaluation requires an explicit target environment: Python version,
implementation, OS, architecture and selected extras/groups. Without a supplied
target, inventory retains conditional declarations and reports activation as
unknown. Running the evaluator on Linux/Python 3.13 does not select a customer's
target environment or satisfy native scanner-image Python 3.14 acceptance.

Corpus v2 root policy: roots are **analysis scopes**, not asserted project
identities. Independently selected inputs in a directory share that directory's
scope; explicit include/constraint targets inherit the referring scope. Paired
manifest/lock files share a scope. First-party applications require manifest/root
evidence and are recorded separately. This policy deliberately separates `a/`
and `b/` dependency inputs and hidden/build directories, without claiming each
directory is a project. Files reused through multiple roots must retain multiple
occurrences. A future explicit configuration may group inputs differently; that
configuration participates in cache identity and must be tested independently.

Generic requirement filenames do not establish runtime/development/build scope
or direct/transitive application relationships: both remain unknown unless
format fields or reviewed configuration prove them. An exact pin is retained as
a declared selection. A Go `require vX` is a declared minimum under MVS, and
cannot become a resolved selection without the required module graph. Python
compatibility declarations (including lock-level `requires-python`) are retained
separately from PEP 508 markers, with unknown activation when no target is given.
Occurrence `requires_python` is package-level metadata, not a copied root policy.
Root applicability and package compatibility are independently located in
`environment_records`; uv's root restriction does not become package metadata.

The S01 evaluator only accepts its synthetic built-in corpus. It uses user,
network, mount and PID namespaces, a read-only/noexec source mount, a scrubbed
environment, two CPU affinity slots, process-tree deadline and per-file output
limits. It is not a production jail: the host filesystem and Unix sockets remain
visible. `noexec` does not prevent an interpreter from reading a script. Raw
process/file/network traces must therefore be reviewed for code execution,
source write attempts and attempted network use. Namespace denial alone does
not prove that an engine's extraction is offline or static. Trace arguments may
be truncated by strace's default string limit; raw traces and stderr are retained.

## Proposed production ceilings

These are rejection/partial-coverage ceilings, not silently truncated success.
Adapters must share the existing global scan deadline and bounded component
parallelism. Inventory must not create another unbounded subprocess pool.

| Resource | Proposed ceiling | Required overflow behavior |
|---|---:|---|
| CPU allocation | 2 logical CPUs per inventory job | Shared worker scheduler/cgroup |
| Resident memory | 2 GiB aggregate process tree | Terminate; partial/failed coverage |
| CPU time | 120 seconds aggregate | Terminate; explicit reason |
| Wall time | 150 seconds, clamped to remaining global deadline | Terminate entire process tree |
| Traversal | 100,000 entries; depth 64 | Report unvisited scope |
| Parsed file | 2 MiB | Record oversized input |
| Aggregate parsed source text | 256 MiB | Report remaining inputs |
| Includes | 64 depth; 4,096 unique targets per root | Cycle/budget error with provenance |
| Package occurrences | 100,000 | Explicit count/budget result |
| Evidenced edges | 500,000 | Explicit graph coverage result |
| Serialized inventory/SBOM | 64 MiB each | Failed serialization, inventory status retained |
| Diagnostic artifacts | 64 MiB per file; 256 MiB aggregate/job | Truncation explicitly recorded |
| Added compressed image content | 250 MiB per architecture | Packaging decision requires measured image delta |
| Raw evidence retention | 7 days in CI, digest-indexed | Preserve public summary/pins in source |

Current evaluator enforcement: CPU affinity, wall/process-tree limit, 2 MiB
synthetic input validation, 64 MiB kernel per-file limit and file descriptor/core
limits. Memory is measured as maximum child RSS, **not aggregate resident memory**.
It does not enforce the full proposed production budgets. Source snapshots prove
retained changes only; attempted denied writes require trace inspection.

## Independent performance corpus to add before freezing

Use generated synthetic exact pins with deterministic identities and independently
known counts: 1,000 / 10,000 / 100,000 package occurrences across 1 / 10 / 100 roots,
and 1,000 / 10,000 / 100,000-entry traversal trees. Add a 64/65-level include chain,
2 MiB boundary file, include-cycle fanout and evidenced graph with 500,000/500,001
edges. Hash generated inputs and scripts, keep expected counts separate from
candidate output, repeat three cold-cache runs and report median/p95 with raw
measurements. Tiny correctness fixtures cannot establish production performance.

Run candidate benchmarks sequentially with no competing job on the same allocated
CPUs. Separate traced diagnostic timing from untraced cgroup performance timing.
Measure aggregate process-tree RSS, CPU/time, archive/binary size and real image
layer delta independently on native AMD64 and ARM64. Distribution assets establish
packaging feasibility only, not native acceptance. Freeze ceilings only after
reviewing those measurements on the dev worker's 8 CPU / 12 GiB allocation.

## Remaining acceptance gates

Independent review of oracle and per-input dispositions; full marker/include/
constraint/monorepo semantics; a substantive Syft cataloger extension if it remains
a candidate (the exact-pin projection probe is intentionally narrow); additional
adapters only where they improve observed coverage; licensed dependency/image
review; stress and native ARM64 evidence; reviewed architecture decision and
frozen budgets. S02/S03 implementation follows that decision. Platform coverage
ingestion/minimal messaging belongs to S05; the SBOM browser belongs to M047.
