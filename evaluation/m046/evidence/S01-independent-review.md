# Independent finite S01 design review

Recommendation: accept the proposed local composition architecture, design
contracts and numerical ceilings as the S01 design decision once the reviewed
decision and retained comparison evidence are published durably. No remaining
design blocker was found in the reviewed decision. This recommendation does
not accept a production engine, distribution, full pipeline performance or
M046 closure.

Reviewed decision: `M046-S01-decision-review-draft.md`, SHA256
`3e77ad214e8742fe238d80c380f4ded959fdbe5e26884cfe01c29cf4afc002ba`.
Maintenance review: `M046-maintenance-feasibility-2026-10-07.md`, SHA256
`50d06f1e0d6c743549398ec0c99cb723efe77e124c7d647221f027e60d07f22e`.
All eleven retained maintenance primary snapshots match their manifest,
SHA256 `b97eeacbc87f7e62bca43e6a5db60da9644c5b691d6d8a1c00fd563f44156135`.
The pinned Syft policy supports only the newest release and excludes malicious
inventory omissions from security scope. The retained latest release is
1.54.1 with deterministic .NET lock resolution and nine dependency changes.
Keeping benchmark pin1.54.0 while requiring a production adoption assessment
is explicit and appropriate. The cdxgen and SCALIBR maintenance descriptions
retain their best-effort and pinned-file/public-policy distinctions.

The design chooses direct canonical Python parsing, restricted pinned Syft raw
evidence for other/installed observations, source-aware canonical adapters and
local CycloneDX1.6 export to Grype. The comparison establishes concrete misses
and operational differences; basic/empty-negative agreement counts are not
accuracy percentages. Optional tools need not receive equivalent production
adapters before this choice. The actual mixed spike proves a minimal join is
feasible while preserving provider authority separately. Its full semantics
and non-Python adapters remain S03 work.

The revised contracts preserve nullable ownership, separately typed analysis
scope, selected/declaration/installed evidence, conditional relationships and
unknown activation. Evidenced edges do not become unconditional standard
export edges; unsupported projection retains explicit loss. Per-input coverage,
graph/version/discovery fidelity and export/matching stages are separate, so a
successful matcher cannot erase partial inventory. Design namespaces are
explicitly independent of prototype versions. S03 must implement the strict
bounded schemas and reproducible serialization before integration.

The native seven-wheel runtime prerequisite is now satisfied on exact PR109
head `d98fbd0fb9c5563999a5c061a12fb68191fddd86`, run37590730428. The independent
runtime report SHA256 is
`3ce965fb4816d1a9e3ada9e6af66bc927cbe84178f998021bdb0982471b5ee45`.
Both API-bound archives,174 inner entries and92 exact evaluation sources per
architecture verified. Both native suites contain49 passing tests. All seven
wheel hashes and runtime code maps match; Python3.14.8/Alpine3.23.6 ran as
UID/GID65534 with configured no-network/read-only/caps-dropped/NNP/2CPU/2GiB/
no-swap/PID32 boundaries, clean exit and confirmed watchdog cleanup. The actual
two-root export preserves both occurrences. The rpds extension and bundled
libgcc were loaded with exact wheel hashes. Independent OCI replay verified
every blob/layer DiffID, baseline13-layer prefix and image defaults; all255
wheel/frontend code files match actual added-layer bytes. Added compressed
cost is1,173,494 bytes AMD64 and1,148,132 bytes ARM64. The old a61027a trial
remains failed; its writer-limit defect and narrow correction are retained.

The numerical freeze is a coherent set of ceilings for the entire pipeline,
not a capacity guarantee or separate allowances per stage. Two CPU quota,
GOMAXPROCS2 and cataloger concurrency2 are distinct from OS thread/PID limits.
Existing measurements establish direct inventory plus CDX through10k flat pins;
they do not establish a complete10k provider/composition/Grype pipeline. The
100k structural ceiling may meet earlier serialization/node bounds and100001
may yield an explicit located omission. Such results cannot become clean or
complete. S06 must measure the combined selected release pipeline, graph and
expansion stress, shared charged memory/CPU/wall accounting and explicit
refusals. Narrower documented capacity is acceptable; silent ceiling growth or
invented completeness is not.

Mandatory later gates remain: S02 production registry and safe discovery; S03
typed canonical adapters and graph/ownership semantics; S04 actual unmodified
native export/Grype compatibility; S05 platform storage/coverage/download; S06
release isolation/cancellation/resource/native/maintenance and complete license
closure; S07 development human and rollback acceptance. Bundled libgcc origin,
notices/source obligations remain a release blocker. Historical literal `???`
traces remain refused; successful finite traces do not prove universal complete
capture, and the Python composition was not traced. No optional kernel policy
or full S03 implementation is imposed as an unstated S01 prerequisite.

This is an independent design recommendation only. It performs no GitHub
review/approval, issue transition, source edit, deployment or milestone closure.
