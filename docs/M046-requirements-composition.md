# M046 S03 source-aware requirements composition

`sourcebastion.inventory.compose_requirements.compose_requirements` consumes one
controller-held S02 `Source` and its discovery result. It emits the draft v1
canonical inventory. This slice implements pip requirement/include/constraint
semantics only. It is not wired into production scans, CycloneDX, Grype or the
platform; S03 and the milestone remain open.

The controller supplies the admitted source digest, separate producer/code
identity, exact registry/config identity, target environment and outer job
resource boundary. Recorded reader/discovery limits must match the actual
Source/config; occurrence limits can be lowered. One Source deadline covers
discovery and composition. Subsequent semantic work charges the same ceiling
using the actual S02 visit counter, including visits deduplicated in its
reference evidence. Source validation runs again before
publishing; detected epoch, deadline or budget failures clear all consumable
records and produce failed inventory. These checks do not establish persistent
custody or prove kernel/cgroup enforcement. Combined release qualification
remains S06 work.

Requirements origins are analysis scopes. No folder name becomes a project root,
installed environment, application or dependency edge. Source graph components
with no incoming include/constraint edges determine origins. Iterative strongly
connected component traversal prevents a cyclic or refused parent from
promoting its descendants into independent authoritative origins. Shared
includes retain separate scopes and selections for each independently evidenced
origin. A constraints-only origin retains declarations and partial coverage,
with no packages. Include references retain their source line, role, target
read hash (or unread status) and refusal. Includes are not dependency edges.

`Declaration` retains requirements and constraints separately from occurrences.
An occurrence can select a version only from an actual exact source pin that
satisfies all applicable source ranges. Typed `selection_declaration_ids` bind
its evidence, identity and analysis context. Duplicate source lines remain
located declarations; equivalent selection contracts share a representative
without creating quadratic evidence lists. Each occurrence reserves weighted
shared charges for evidence expansion and repeated range validation before
allocating its selection links. A cumulative minimum-node check bounds link
expansion, then a lazy structural preflight runs before full Inventory
revalidation. Later serialize/export stages must remain inside the same outer
job budget; this adapter does not grant them fresh allowances. Unused constraints do not become
packages. Ranges do not acquire guessed, worker-installed or registry versions.
Artifact hashes are preserved without asserting installation or downloaded
artifact verification.

Default environment policy preserves conditional alternatives with unknown
activation. Explicit target evaluation uses recorded values only. Narrowly
proved equivalent marker contexts share evidence; proved disjoint alternatives
retain their own pins. Conflicting declarations, ignored/missing/refused
required includes, constraint extras, unproved conditional constraints and
overlapping incompatible marker alternatives prevent selected versions in the
affected origin. Unrelated admitted origins remain visible in partial results.
Graph and environment fidelity remain unknown even for complete flat pins.

The draft structural contract adds located `Declaration`, `InputReference` and
`Applicability` records plus occurrence selection references. Applicability
provides typed Python-version, marker and group conditions for later adapters;
the requirements adapter keeps PEP508 conditions on declarations/occurrences.
Every new source record binds a read-hash coverage entry; references also bind
target coverage and scope. Validation checks internal consistency, not the truth
of controller assertions or the adapter's actual source interpretation.

Known non-pip inputs remain explicitly unsupported. Static Python manifests and
locks, non-Python canonical adapters, provider joining, rich corpus agreement,
CycloneDX projection, real matching, complete resource qualification and human
development acceptance remain required in subsequent M046 work. The historical
S01 oracle's inferred folder roots are not silently adopted as project evidence.

The native installed-wheel probe exercises finite source/constraint/context and
refusal assertions, then records repeated canonical digests for all 64 frozen
fixtures. Repeated digests measure deterministic behavior, not full semantic
agreement or coverage. It records the actual installed module hashes and
runtime versions on each architecture. Requested Docker flags are not retained
proof of actual kernel enforcement or attempted network/process operations.
