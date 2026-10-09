# M046 S03 acceptance boundary

Scanner issue 91 is the authoritative acceptance status and evidence record.
The public scanner route remains legacy; S03 implements the internal canonical
source composition API.

Implemented foundations include strict canonical records and reproducible
serialization, content-bound requirements/constraints, static Python metadata
and all scoped Python lock families, npm/pnpm/Yarn/Cargo/Go/Gradle adapters,
installed Python metadata evidence, conservative NuGet v1/v2 composition and
limited Bundler/Composer locked package enumeration.
The full source-authored expectation set covers 64 unchanged historical inputs.

Acceptance checklist:

1. Use the documented supported subsets and explicit unsupported dispositions
   as the ecosystem acceptance boundary. The owner confirmed on 2026-10-09
   that legacy scanner coverage parity is not required because the scanner has
   no users. Ruby/PHP acceptance covers the bounded Bundler/Composer subsets;
   broader native/source/provider support is future work, not a parity gate.
2. Verify full source-authored record, package/version, evidenced-edge and
   disposition agreement in installed native AMD64 and ARM64 builds at the
   exact proposed head. Local Linux unit tests alone do not satisfy this gate.
3. Review the complete adapter support matrix and canonical contract against
   S03's multi-root, conditional/alternative, conflict and flat-lock demo.
4. Record the acceptance review and evidence on scanner issue 91. S04 actual matching,
   S05 persistence, S06 release resources and S07 live acceptance remain
   separate obligations; completing S03 does not activate the customer route.

Current NuGet change also carries the exact-file-set proof correction already
reviewed in draft PR146: nonempty installed inventory maps must equal checkout
path/hash maps, and the wheel payload map must equal the complete expected
distribution set. New adapters do not require guessed fixed file counts.
