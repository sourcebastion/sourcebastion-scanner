# M046 S03 acceptance work

S03 remains open. Work continues in an isolated checkout; the public scanner
route and other agents' implementation branches are unchanged.

Implemented foundations include strict canonical records and reproducible
serialization, content-bound requirements/constraints, static Python metadata
and all scoped Python lock families, npm/pnpm/Yarn/Cargo/Go/Gradle adapters,
installed Python metadata evidence and conservative NuGet v1/v2 composition.
The full source-authored expectation set covers 64 unchanged historical inputs.

Before acceptance:

1. Preserve or explicitly disposition legacy ecosystem package coverage. The
   canonical Ruby/PHP fixtures currently emit no package records, unlike the
   historical inventory oracle; Maven/project/installed observations also need
   their source/provider boundary reviewed. Do not silently relabel these as
   full preservation.
2. Verify full source-authored record, package/version, evidenced-edge and
   disposition agreement in installed native AMD64 and ARM64 builds at the
   exact proposed head. Local Linux unit tests alone do not satisfy this gate.
3. Review the complete adapter support matrix and canonical contract against
   S03's multi-root, conditional/alternative, conflict and flat-lock demo.
4. Record independent review/acceptance on scanner issue 91. S04 actual matching,
   S05 persistence, S06 release resources and S07 live acceptance remain
   separate obligations; completing S03 does not activate the customer route.

Current NuGet change also carries the exact-file-set proof correction already
reviewed in draft PR146: nonempty installed inventory maps must equal checkout
path/hash maps, and the wheel payload map must equal the complete expected
distribution set. New adapters do not require guessed fixed file counts.
