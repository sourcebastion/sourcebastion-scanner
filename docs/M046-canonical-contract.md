# M046 S03 canonical contract foundation

The accepted S01 architecture is recorded in merged PR110 and
`evaluation/m046/architecture-decision.md`. This slice defines production
`sourcebastion.inventory/1`, `inventory-coverage/1`, `environment/1` and
`inventory-limits/1` records in `sourcebastion.inventory.contract`, with a
[structural schema snapshot](M046-inventory-v1.schema.json). The [requirements composition slice](M046-requirements-composition.md) adds
source-aware pip composition and explicit-target marker evaluation. Source/provider
joining, other canonical adapters, CycloneDX export, matching and production
scanner integration remain incomplete. S03 remains open.

Strict frozen records reject unknown fields, invalid digest/ID namespaces,
noncanonical outside-root source paths, contradictory name/version/purl fields,
unbound references, duplicate IDs/coverage paths and limits above the S01
ceilings. Serialized records are revalidated, including nested instances, so
Pydantic's trusted `model_copy`/construction escape hatches cannot silently
bypass output validation. Structural validation does not authenticate controller
source/producer assertions or prove that an adapter established source semantics.
Adapters and the controller remain responsible for those facts.

A root record asserts an evidenced source project. Analysis scopes such as a
requirements origin, lock input or provider directory have a separate namespace.
An occurrence may have unknown project ownership (`root_id=null`) and a known
analysis scope. Installed observations retain a separately evidenced environment
or unknown ownership; they cannot borrow a source project root. Equal purls do
not erase occurrences with different source locators, roots or environments.

Occurrences keep exact selected versions separate from ranges, and distinguish
`declared`, `locked` and `installed` evidence. A selected source pin does not
assert installation. Adapters must canonicalize ecosystem identities before
construction; the structural purl check verifies internal agreement, not package
registry authenticity. Directness, scopes/groups, hashes, markers, extras and
activation remain explicit. Go module-tree hashes use a distinct `go-h1` type,
not a claim that the value is a raw file SHA256. Optional provider references
bind a separate raw sidecar and record hash, without copying raw metadata or
conferring matching authority.

The internal `go-h1` digest is lowercase decoded SHA256 hex. `go_module_hash`
strictly and reversibly converts Go's canonical `h1:` plus 44-character base64
form; an adapter must use this conversion rather than treat go.sum text as hex.
PyPI names must already have PEP503 case/separator normalization and selected
versions must already be canonical PEP440. Maven/Composer identities require a
namespace and npm scopes require both namespace and package. Other version
fields receive conservative syntax checks; npm/Cargo/Go selected versions use
strict SemVer (with Go's `v` prefix), and common unresolved aliases are refused.
NuGet/Composer names must already be lowercased. Ecosystem adapters must establish
resolution semantics before assigning a selected version.
These identity conventions follow the maintained upstream
[PURL type definitions](https://github.com/package-url/purl-spec/tree/main/types),
[PyPA name normalization](https://packaging.python.org/en/latest/specifications/name-normalization/)
and [Go checksum representation](https://go.dev/ref/mod#go-sum-files).

Relationship endpoints must bind actual occurrence IDs. `evidenced` and
`unassessed` remain distinct; the latter cannot enter matching. Conditions,
extras/scopes and unknown activation remain attached to evidenced relationships.
Typed projection losses bind the affected source/occurrence/relationship.
Export must retain such losses rather than turn a conditional relationship into
an unconditional edge. Source include/constraint references are not dependency
relationships. Source adapters, not the schema, establish the graph evidence.

Environment defaults to preserving alternatives with no target fields. An
explicit target records supplied implementation/version/platform/architecture
and named PEP508 marker inputs; conflicting/duplicate inputs are refused.
`marker_environment` contains only supplied or deterministic target-derived
values, with no worker host fallback. A minor-only Python target does not invent
a full patch version. This contract module does not evaluate markers; the reviewed marker helper
uses explicit target inputs only. Missing inputs or unresolved extra/group
activation remain unknown.
Environment identity is digested independently of provider/config versions.

Per-input discovery/parsed/ignored/unsupported/failed/omitted/unresolved records
and independent discovery/enumeration/version/graph/environment fidelity prevent
successful matching from upgrading partial coverage. Inventory `complete`
requires complete discovery, enumeration and version resolution with no pending
or refused input; it still does not claim known graph/environment fidelity.
Global refusal codes also prevent promotion. A null selected version cannot
coexist with complete version resolution, and a null purl prevents complete
inventory. Every retained record's source path and SHA256 must bind a read-hash
coverage entry. These checks enforce internal agreement, not proof of a read.
Coverage may carry bound root/analysis/installed-environment context IDs or empty
contexts for unknown ownership. Input ownership does not assert that an entire
root's inventory is complete; per-root completeness remains unassessed here.
Those dimensions remain visible independently (flat pins can have unknown edges).
An inventory with unsupported/unresolved input stays partial even if matching
succeeds. A failed inventory admits no occurrence graph; matching requires an
admitted export. Matching failure preserves already admitted inventory.

The source SHA256 is the trusted controller's admitted-source assertion, not a
digest inferred from recognized files. Producer/code/registry/config and target
identities have separate fields. The limits record states the shared pipeline
ceilings; it does not allocate fresh allowances per stage or prove actual kernel
enforcement. S06 must verify combined release resource/isolation/cleanup policy.

`canonical_bytes` revalidates records, sorts record IDs/input paths/environment
marker inputs and emits deterministic compact JSON within the effective 64MiB
and 2M-node maxima (or configured lower limits). Overflow refuses with no
truncated valid-looking output. Constructing/loading records must occur inside
the controller's bounded job; this is not an unbounded external JSON ingestion
endpoint. S05 must enforce transport/retention/access budgets separately.
Before graph revalidation or JSON materialization, it validates the small limits
record and lazily preflights the existing object structure against effective
node/depth/string limits. Iterator frames avoid allocating whole child lists
when reduced node limits refuse dense inputs.

Contract tests cover distinct equal-purl roots, unknown analysis ownership,
installed/source separation, conditional edge losses, bound endpoints, ranges,
strict nested-instance revalidation, target conflicts/no host fallback, shared
numerical ceilings, stage independence and deterministic budgeted serialization.
Full S03 adapter corpus, non-Python support matrix and S04/S06/S07 native/runtime
acceptance remain mandatory; this contract foundation closes none of them.
