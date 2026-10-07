# M046 S01 architecture decision

Status: independently reviewed S01 design, proposed for adoption by merging this
documentation PR. Native Alpine feasibility passed on both architectures. This
is not production engine release acceptance or closure of M046. The independent
review recommends acceptance of the architecture, contracts and numerical
ceilings, with mandatory S02–S07 delivery gates below.

Choose one local composition architecture: direct canonical Python source
parsers, a pinned restricted Syft evidence provider for non-Python/installed
observations, source-aware canonical adapters, and CycloneDX 1.6 to the existing
local Grype matcher. Keep provider output and canonical authority separate.
S02/S03 implement the production registry and adapters after this design is
accepted. Do not ship the evaluation prototype as a complete inventory engine.

## Decision evidence

The independent 64-case corpus spans Python, Node, Go, Rust and broader existing
ecosystems, positive/negative/adversarial inputs, custom and hidden filenames,
includes/constraints, unresolved and conflicting declarations, markers/extras,
multiple roots and malformed/dynamic metadata. Expected packages, evidenced
edges and dispositions were reviewed independently of candidate output. The
installed ownership probe is separately labelled, not a replacement corpus case.

Retained stock-tool data covers 60 common identical original inputs, two AMD64
attempts each for Syft 1.54.0, cdxgen 13.3.0, SCALIBR 0.5.3 and the transformed
exact-pin projection. Four later cases are not evaluated for these profiles.
All 480 attempts were re-compared with the current oracle with original trees,
transformation maps, imported code and raw/trace identities checked before and
after. Basic agreements are 38/32/38/43; also-exact application identities are
37/9/38/42; rich full-contract agreement is zero for those exporter profiles.
Empty negatives count as agreements; these are not accuracy percentages.

cdxgen's evaluated hosted profile attempts Go project tooling, follows the
synthetic outside-root symlink and turns a Python range into its floor version.
It fails the current static-hosted boundary. SCALIBR omits tested edges and
changes root/module representations. Neither justifies full parity adapters for
every rival before making this architecture decision. ORT and CycloneDX Python
remain optional future ecosystem adapters, with no advertised-support credit.

The direct Python route has 40 rich reviewed contracts with native evidence.
The substantive Syft extension actually invokes that frontend and preserves a
sidecar, but adds a conversion/projection boundary without a demonstrated need
in this preferred route. Its historical undecoded traces remain refused.
The restricted provider retains raw IDs, types, purls, locations and metadata
without promoting declaration/versionless/application observations to selected
canonical dependencies. Complete source-aware adapters remain S03 work.

PR108 exact-head native run37588602868 independently verified all 260 provider
and four mixed attempts, 1,145 inner hashes and 88 evaluation files per
architecture, current source, native binaries/pins and 147 tests/architecture.
258 provider strict traces admitted; two literal undecoded calls remain refused.
Every case has at least one admitted provider repeat on each architecture. All
four mixed provider traces admitted. The Python composition itself was not
traced. The two-root mixed composition is repeat/cross-architecture identical:
2 source occurrences, 7 provider records and 2 unassessed contextual edges.
These are finite observations, not a universal isolation guarantee.

Independently measured 2-CPU/2-GiB charged-memory native trials demonstrate direct
inventory plus export through 10k flat pins. At 100k, inventory completes but
export refuses its 2M-node limit. At 100001, inventory reports explicit partial
budget omission. CPE-off reduces small/medium provider cost; it does not repair
large-output or undecoded-trace failures of the conversion route.

The existing static Go overlay works on actual scanner Python3.14.8/Alpine3.23
on both architectures, with roughly 52/48 MB added compressed layers. The
separate seven-wheel direct schema-stack proof at PR109 head
`d98fbd0fb9c5563999a5c061a12fb68191fddd86`, run37590730428, passed independently
audited native AMD64/ARM64 execution on Python3.14.8/Alpine3.23.6. It verifies
actual imports, a source-bound two-root export, exercised rpds/libgcc identities,
all 255 installed wheel/frontend code files against added OCI layer bytes,
and the unchanged baseline 13-layer prefix/configuration. Added compressed
growth is 1,173,494 bytes AMD64 and 1,148,132 bytes ARM64. Both architectures
passed 49 runtime/OCI tests. The old a61027a OCI-export attempt remains failed;
its narrowly corrected writer limit is not a waiver of artifact verification.

The [evidence index](evidence/README.md) binds the reviewed source heads, native
runs, independent audit reports and reproducible retained comparison. The
[finite independent review](evidence/S01-independent-review.md) reviewed the
pre-publication decision SHA256
`3e77ad214e8742fe238d80c380f4ded959fdbe5e26884cfe01c29cf4afc002ba`;
this publication updates status, verified runtime facts and evidence links,
without changing the reviewed contract or numerical ceilings.

## Contract and authority

The production inventory/coverage contract is versioned independently of raw
provider APIs and evaluation prototype versions. Its required fields cover
source identity; root/environment identity; located occurrences; ecosystem,
canonical name/purl; selected versus declared/installed version evidence;
hashes/ranges; direct/transitive/unknown classification; groups/scopes,
markers/extras; contextual relationships; and per-input dispositions/losses.
S03 must publish the exact production schema and reproducible serialization.

Freeze the design namespaces as `sourcebastion.inventory/1`,
`sourcebastion.inventory-coverage/1`, `sourcebastion.environment/1` and
`sourcebastion.inventory-limits/1`. These are design contract versions, not a
claim that evaluation `prototype-v5` output already implements them. S03 must
implement strict bounded schemas against this design before integration.

`inventory/1` contains a source digest, producer/parser/registry/config digests,
an environment record, typed root records, occurrence records, relationships,
application metadata, coverage and independent stage states. IDs and digests
are nonempty namespaced strings and lowercase SHA256 respectively; paths are
bounded root-relative POSIX strings, never absolute or parent-traversing.
Occurrence fields include a located source record, ecosystem/name/purl,
`evidence_kind` (`declared`, `locked`, `installed`), nullable exact selected
version, retained nullable declared range, hashes, root ID, nullable installed
environment ID, scopes/groups/markers/extras and directness
(`direct`, `transitive`, `unknown`). Root and installed-environment IDs may be
null when ownership is unknown; separately typed analysis-scope IDs do not
assert canonical project ownership. Unselected declarations cannot masquerade
as selected versions; installed evidence never borrows source-root ownership.
Relationship endpoints are occurrence IDs with evidence locators and an
`evidence_status` (`evidenced`, `unassessed`); only evidenced relationships may
enter the canonical matching graph. Relationships retain scopes, markers,
extras and activation context. Evidenced does not imply active/unconditional:
unknown or conditional edges remain canonical evidence, with explicit loss if
standard export cannot represent their conditions safely. Raw provider IDs
remain separately typed.

`environment/1` has policy (`preserve-alternatives`, `explicit-target`), nullable
Python implementation/version/platform/architecture marker inputs and their
digest, with activation (`active`, `inactive`, `unknown`). An explicit target
requires all fields needed by a tested marker expression; missing inputs retain
unknown activation. No host fallback or dependency resolution is permitted.

`inventory-coverage/1` has per-input/root evidence with source hashes where read,
format/parser versions, disposition (`discovered`, `parsed`, `ignored`,
`unsupported`, `failed`, `bounded-omission`, `unresolved`) and bounded reason
codes. Each dimension states `complete`, `partial`, `unknown` or `failed` and
keeps discovery, version and graph fidelity separate. Inventory stage is
`complete`, `partial` or `failed`; export and matching each use `not-run`,
`succeeded` or `failed`. Successful export/matching cannot upgrade partial or
unknown coverage. Unsupported/malformed/ambiguous inputs cannot yield complete
coverage by returning empty arrays. Credentials/options in source URLs never
enter customer-facing metadata; safe locations and reason codes suffice.

Equal purls never erase distinct roots, installed environments or source
locators. Source declarations do not claim installation. Flat locks never invent
package-to-package edges. Unpinned ranges remain unresolved. Provider raw IDs
and source hashes bind observations, but a directory alone does not prove a
project or installed environment. Unknown ownership/activation remain explicit.
Malformed or contradictory identity evidence refuses admission.

Environment interpretation is a typed, digested input. Default hosted scanning
preserves all evidenced alternatives with unknown activation; it does not use
the worker's Python/platform as the customer's target environment. An explicit
target may evaluate markers only under the reviewed policy, retaining the
original condition and provenance. It grants no resolution/network authority.

Discovery completeness, version resolution, graph fidelity, SBOM export and
matching are separate statuses. Unsupported/ignored/failed/bounded omissions
are located coverage dispositions. No recognized manifest is legacy/unknown
coverage, not proof of no dependencies. Matching failure preserves inventory.
Export refusal retains bounded diagnostics and does not produce a truncated
valid-looking SBOM. Existing clients without coverage remain legacy/unknown.

The controller owns immutable input, admitted roots, source and tool hashes,
offline policy, deadlines, cancellation and child cleanup. Customer mappings
cannot grant execution, network or outside-root authority. Maintenance downloads
and advisory preparation occur separately from scanning. No per-scan forge API
or source build/installation is permitted. Production isolation and actual
release/native verification remain S06/S07 acceptance obligations.

## Numerical freeze v1

All following ceilings apply to the complete dependency pipeline, including
discovery, provider, canonical composition, serialization, export and matching.
They are not fresh allowances per stage. Lower limits imposed by the existing
outer scan/global deadline always win. Customer configuration may reduce, not
increase, hosted limits. Any exception needs a recorded scope/budget revision.

| Resource | Ceiling |
| --- | ---: |
| CPU quota / Go scheduling / cataloger concurrency | 2 CPUs / GOMAXPROCS=2 / 2 |
| Kernel-charged cgroup peak memory | 2 GiB |
| Swap | 0 |
| Aggregate cgroup CPU time | 120 seconds |
| Pipeline wall time, clamped by outer deadline | 150 seconds |
| PIDs in dependency job | 256 |
| Traversal entries / depth | 100,000 / 64 |
| One parsed source / total parsed text | 2 MiB / 256 MiB |
| Include depth / targets per root | 64 / 4,096 |
| Located occurrences / canonical edges | 100,000 / 500,000 |
| Semantic resolution or edge-context checks | 5,000,000 |
| Complete inventory / complete SBOM | 64 MiB each |
| One diagnostic artifact / total diagnostic bytes per job | 64 MiB / 256 MiB |
| Structured export tree nodes / depth / one string | 2,000,000 / 32 / 2 MiB |
| Added compressed release layers per architecture | 250 MiB |

The structural 100k occurrence ceiling is not a complete-export promise. The
current measured complete envelope is 10k flat pins, not arbitrary graphs of
that size; this covers direct inventory plus CDX only, not the complete provider
and Grype pipeline. Go can legitimately create more than two OS threads under
the PID limit; CPU quota and scheduler/cataloger concurrency are separate.
Dense graphs, large metadata and serialization can refuse earlier;
every refusal is explicit and remains partial/unavailable. S06 measures the
complete selected release pipeline on the frozen corpus, including graph and
expansion stress, before release. It may require optimization or narrower
documented capacity, never silent ceiling growth or unsupported clean results.

The reproducible corpus is the source-bound 64-case corpus plus separately
labelled installed/mixed probes and immutable performance generators: 1k, 10k,
100k and 100001 flat pins with independent hashes/root oracles, and the retained
small/medium/large conversion controls. Repeat each resource arm three times per
native architecture in fresh cgroups. Full graph/expansion and aggregate-stage
release workloads must be added in S06 with independent expectations.

## License and maintenance feasibility

Candidate projects declare Apache-2.0. The direct stack contains MIT,
Apache/BSD and reviewed Rust dual-license categories. Exact musl rpds publisher
subjects/workflow identity and hashes were independently verified; license
texts from seven wheels and 18 pinned Cargo archives were inspected as data.
Both musl wheels bundle libgcc_s.so.1 without an accompanying vendor notice.
Its precise origin, notices/source obligations and final distribution closure
remain explicit S06 release blockers. No incompatible license has been
established; architecture feasibility is not distribution clearance.

SourceBastion scanner maintainers own the registry, canonical adapters, engine
pins, schemas and corpus. Pin source/tool/wheel/config/registry identities and
advisory snapshot in outputs and cache keys. Upgrade reviews must show package,
edge, coverage, finding and resource/image differences, repeat affected native
tests and preserve offline behavior. Provider/schema/registry versions evolve
independently. S06 publishes the support matrix, cadence and release runbook.

The dated maintenance review is
[maintenance review](maintenance-review.md), backed by primary API/policy snapshots.
Syft 1.54.1 is newer than the evaluated pin; its .NET deterministic-lock and
dependency changes require an S06 adoption assessment before production.
Benchmark pins stay frozen for this decision. Weekly upstream review and
pre-release review are proposed maintainer responsibilities, with no recurring
automation created. SourceBastion owns malicious-input coverage and containment
even where upstream policies exclude inventory omission from security scope.

## Acceptance boundary and next slices

Independent review of the decision, corpus/comparison, design contracts and
numerical freeze recommends S01 acceptance; the finite native mandatory-runtime
proof is verified. Merging this reviewed decision records design adoption.
Do not require complete S03 production adapters before selecting their design.
Do not add an optional kernel-policy project as an unstated S01 prerequisite.
Reopen selection only for a named unmet mandatory requirement and a concrete
alternative, rather than cycling through full implementations of every tool.

Then deliver S02 registry, S03 canonical adapters and semantics, S04 export/local
Grype compatibility, S05 designed platform storage/coverage/download, S06
release/native/license/maintenance gates, and S07 verified dev human/rollback
acceptance on the existing 8-CPU/12-GiB worker. M047 owns the SBOM browser;
platform #375 owns persistent scan-error UX; M044/M045 remain separate.
No live rollout, recovery adoption, LOGIN compensation or milestone closure is
authorized by accepting this architecture document.
