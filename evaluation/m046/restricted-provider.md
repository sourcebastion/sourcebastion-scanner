# Restricted non-Python and installed evidence provider

This is a finite S01 selection diagnostic, stacked on the direct resource
candidate. It does not select an engine or change production scanning.

The pinned Syft1.54 library gets a separate `--mode provider`. Its package
catalogers are an explicit list: JavaScript lock/installed package, Go module
file, Cargo lock, installed Python, Gradle lock, POM, .NET lock, Bundler and
Composer lock. CPE generation, remote licenses, Go packages-library execution,
module-cache/vendor license lookup, Maven network/transitive lookup and Vcpkg
cloning are disabled in the existing explicit profile. Source providers remain
explicit directory only. File evidence tasks may still run; named package
catalogers do not by themselves establish an execution or traversal boundary.
The historical control and extended modes keep their previous profiles.

Python declaration files belong to the direct canonical frontend. The provider
retains installed Python metadata separately. A Go `require` or POM version is
only a declared-version candidate: it cannot become an installed/selected
version merely because Syft emits an exact-looking purl. All raw provider IDs,
paths, metadata and dependency direction survive in a separate facts document.
Path hashes come from retained controller snapshots; they prove neither
cross-call descriptor custody nor source record locators. Raw duplicate
identities at different paths remain separate. No name/purl-only joining or
inferred project root is permitted.

The adapter explicitly leaves per-input parse outcomes, canonical record/root,
scope/environment/declared-range, application role and complete graph semantics
unassessed. Raw metadata may contain useful hints, but it is retained without
promoting those hints to the canonical contract. The side-by-side comparison
uses independent expectations only after extracting facts; empty negative
output never proves safe rejection or complete coverage. Required Node, Go,
Rust and installed-Python behavior cannot be declared unsupported simply to
select this provider.

The frozen64-case corpus plus one labelled installed-Python ownership regression runs twice per native architecture with read-only
synthetic sources, environment scrubbing, network namespaces and retained raw
process/network/file traces. Each strict trace admission is separate from raw
fact collection; undecoded capture remains refused and visible. Source/binary
uncertainty aborts. Fact/trace refusals remain invalid diagnostic attempts and
are not hidden by workflow completion. This is not an aggregate cgroup
performance or actual Alpine image qualification. Three proposed successful
limits remain distinct: 100k inventory structural maximum, independently
bounded export representation, and a measured operating envelope.

Selection should converge after this pass: direct Python plus one restricted
provider with explicit canonical adapters, or one named challenger pivot for a
precise unmet must-have. cdxgen/SCALIBR need honest observed/unreported axes,
not full equivalent production implementations. The final architecture still
requires typed composition/merge, complete selected-route offline evidence,
image/vendor licenses, maintenance ownership and reviewed numerical budgets.
