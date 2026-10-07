# Restricted provider evidence

The restricted provider is a pinned Syft 1.54.0 library executable, built with
hash-pinned Go 1.27.1 and its committed module sums. It is a supporting evidence
producer for M046, separate from the production scanner's existing Grype route.
The executable is not yet shipped in the release image or called by that route.
No canonical inventory, SBOM, matching or complete graph authority follows from
a successful provider process or receipt.

The profile enables ten package catalogers for Node locks/manifests, Go module
files, Cargo locks, installed Python metadata, Java POM/Gradle locks, .NET locks,
Bundler locks and Composer locks. Four implicit Syft file catalogers also run.
Python source declarations are owned by the direct canonical adapters. CPE
generation, known remote enrichment, package/project tooling, Go local module
and vendor license lookup, Maven local repository lookup and transitive
resolution are disabled. File data generation hashes observed owned files.
These configuration assertions do not establish a network or execution fence.

The controller must supply an admitted, materialized, read-only source snapshot
and the remaining shared deadline. The CLI accepts an absolute directory root,
a positive remaining duration no greater than 150 seconds, and an output ceiling
no greater than 64 MiB. It sets two Go schedulers and two cataloger workers. It
retains the complete JSON before stdout and checks final package/relationship
counts. Syft allocations before these checks still require the outer memory,
CPU, process and wall boundaries. There is no new per-stage resource allowance.
Source snapshot materialization and persistent custody are not implemented by
this executable. In particular, its root check does not fence nested symlinks,
same-UID writers or a hostile administrator.

`bind_provider` consumes private provider JSON, the same controller-held Source
and its already-produced discovery result. It requires the caller's existing
semantic accounting callback. Byte/depth/node/string and record ceilings,
duplicate-key/nonfinite refusal, the exact cataloger/offline profile, package
types, confined locations and observed regular-file SHA256/size are checked.
Metadata representations are admitted by an explicit cataloger-to-schema table;
Ruby lock observations explicitly allow the absence of metadata in this pinned
Syft version. Unknown representations are refused. Non-dependency relationships
are counted as uninterpreted observations, not promoted to canonical graph data.
Every observed file must match an admitted input in the held Source cache.
Final source epoch validation precedes publication. Any refusal returns no
receipt; diagnostics contain fixed codes, including typed-validation failures
whose underlying exceptions could otherwise expose input values. Kernel limits remain necessary during
JSON decoding and Syft conversion.

The typed receipt preserves raw provider identifiers, source file bindings,
canonical-format observed identities when available, and separate raw record
and output hashes. Syft's dependency-of direction is normalized into a provider
relationship with both raw endpoints. Equal purls never join occurrences or
projects. A Node lock root may represent the application itself; a Go module
version is a source declaration; installed Python metadata does not establish
that a source manifest selected it. All candidate roles and relationships retain
unassessed canonical semantics. Missing versions and unsupported identities
stay explicitly unselected. No per-input parse completeness is inferred from
an empty provider result.

The caller's whole-source digest and binary digest are controller assertions,
structurally checked rather than authenticated or recomputed from a whole
repository by this bridge. Observed file hashes are compared to actual held
Source bytes. A restricted executable or receipt alone cannot prove custody of
the process, snapshot or complete source tree.

Raw source paths, metadata, registry URLs and other provider properties remain
in the private sidecar; the receipt copies no raw metadata or host root path.
Source paths are relative repository evidence, and package identities are
admitted only when their exact purl matches the strict canonical representation.
Unknown or qualified identities retain their record hash without publishing
their untrusted identity fields. A raw record digest is the SHA256 of its sorted
compact JSON encoding; the provider output digest covers the exact raw bytes.

Native probes build this standalone executable in trusted preparation, then
mount it into the actual scanner image and load the installed Python bridge.
They exercise Node application/root separation, source declarations versus
installed Python, versionless metadata, Go declarations and Cargo observations,
with repeatability and source hashes. Requested Docker restrictions do not
replace S06's actual kernel/resource/cancellation/trace evidence. Probe fixtures
are writable temporary directories; before/after byte equality records the
observed unchanged source, without proving a read-only snapshot. These finite
cases do not establish rich corpus accuracy, complete ecosystem support,
production routing, full dependency graphs, SBOM export or M046 closure.
