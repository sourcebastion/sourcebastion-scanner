# Canonical NuGet lock evidence

The inactive `compose_source` pipeline admits a conservative subset of
`packages.lock.json` versions 1 and 2. It reads source bytes through the existing
descriptor-held reader, shares the composition deadline/work ledger and refuses
global record overflows without publishing a selected prefix. No NuGet restore,
MSBuild evaluation, package installation or customer command is executed.

Each framework/RID table gets its own located analysis scope. Distinct source
files and target tables retain separate occurrence IDs even when purls agree.
A lock table does not establish a project root, installed environment or active
customer target. Names use NuGet's case-insensitive identity; case-colliding
entries refuse the input rather than silently overwriting a selection.

Explicit resolved versions remain locked selections, separate from requested
ranges. Direct, Transitive and CentralTransitive entries retain their stated
directness. Valid canonical base64 SHA512 content hashes become typed integrity
evidence. A missing/invalid hash leaves package/version evidence available while
input coverage remains partial; it never becomes a fabricated hash.

Dependency selectors retain the source name/range and bind only a package in
the same lock file and exact target table. The reviewed `nuget-release-range-1`
dialect verifies numeric release minimums, exact brackets and bounded/unbounded
intervals. Bare NuGet versions are minimums. Floating, prerelease and other
unassessed ranges retain unresolved selectors. Missing or contradictory
endpoints produce no edge. RID delta tables never borrow base-framework rows.
Graph coverage remains partial and target activation unknown even when all
retained selectors have endpoints.

Version 3's target-alias representation, project references, unknown controls
and other unsupported sources remain explicit omissions. Adjacent
`packages.config` and project XML are still unsupported canonical inputs. No
legacy dependency scan route is replaced by this adapter.

The original .NET corpus bytes are unchanged. The source-authored canonical
expectation now retains `newtonsoft.json@13.0.3`, its requested range and exact
framework context, with partial hash coverage because the historical fixture's
`contentHash` is the literal `fixture`. Tests cover actual composition,
round-trip/repeated canonical bytes, multiple roots/frameworks/RIDs, range
boundaries, unresolved/contradictory endpoints, duplicate/case-colliding keys,
redaction, source mutation and whole-inventory budget refusal.

The implementation follows the upstream
[NuGet lock representation](https://github.com/NuGet/NuGet.Client/blob/dev/src/NuGet.Core/NuGet.ProjectModel/ProjectLockFile/PackagesLockFileFormat.cs)
and [version-range semantics](https://learn.microsoft.com/en-us/nuget/concepts/package-versioning#version-ranges).
Full legacy ecosystem preservation, exact native corpus proof and independent
S03 acceptance remain required. This change does not close S03 or M046.
