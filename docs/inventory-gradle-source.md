# Static Gradle lock source inventory

The canonical adapter reads the modern generated Gradle lockfile format:
`group:artifact:version=configurations`, comments/blank lines, and a terminal
`empty=configurations` row. It recognizes `gradle.lockfile` and
`buildscript-gradle.lockfile`; bounded explicit registry mappings can admit
custom names. The format authority is the
[Gradle dependency locking manual](https://docs.gradle.org/current/userguide/dependency_locking.html).
No Gradle project code, wrapper, JVM, package resolution or network is invoked.

Validated fixed coordinates become locked Maven occurrences with the original
file hash and line locator. Configuration names are retained as source scope
labels, with no runtime/dev interpretation. A lock-input analysis scope does
not establish project ownership or an installed environment. Directness and
activation remain unknown; the flat lock creates no dependency edges. Locked
selection does not prove installed version, artifact integrity or a successful
build. Different versions in disjoint configurations and repeated coordinates
in separate files remain distinct contextual occurrences.

The supported representation uses conservative ASCII coordinate/version and
configuration tokens. Ranges, wildcards, latest/interpolation/URL forms and the
legacy per-configuration format remain unsupported. Missing the modern terminal
marker cannot produce clean empty inventory. Duplicate coordinates/configuration
labels, conflicting versions in one module/configuration, populated-but-empty
configurations and invalid encoding/control bytes refuse all selected authority
for that input, retaining typed partial coverage. Independent language evidence
is retained on an ordinary input refusal. Named empty configurations retain a
located scope loss; they do not assert absence of dependencies in the project.

Configuration expansion is capped at64 labels per line and charges the shared
semantic ledger. All parsed occurrences charge the aggregate occurrence and
structure limits; global budget/source uncertainty clears candidate records
through the existing composition refusal path. The source is validated before
and after composition.

The original Gradle corpus fixture has a source-authored full-record expectation
reviewed before first adapter execution. The historical64 oracle remains
unchanged: its directory root and unconditional activation are explicitly
replaced here by unknown ownership/activation in the canonical contract. Native
installed-image proofs are required before merge. This adapter does not switch
the released dependency scan route, complete Java support, preserve all other
legacy ecosystems or close S03/M046.
