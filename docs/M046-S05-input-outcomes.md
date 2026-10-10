# Producer input outcomes for S05

`InputCoverage` now records the producer's maintained format-to-ecosystem
dispatch identity, including unsupported, ignored, unresolved and explicitly
empty inputs. Package presence is not an ecosystem or completeness oracle.
The dispatch map is part of the registry digest, so changing it invalidates
incompatible runtime and component identities.

`enumeration_basis=source-input` restricts the input's enumeration outcome to
the records encoded by that input. Parsed input records have complete input
enumeration; unresolved or bounded inputs are partial; parser failures are
failed. Unsupported, ignored and unexamined inputs remain unknown. A complete
input outcome requires a parser and admitted source digest. It never means a
complete installed dependency closure, full graph, all dependencies in a
directory, or all ecosystems in a project. Global inventory, version, graph
and discovery fidelity remain separate and unchanged.

Existing evidenced root, analysis-scope and installed-environment associations
bind these outcomes to their contexts. Unbound ownership stays unknown; folder
proximity does not create a project. An explicitly empty Gradle lock retains
its Maven ecosystem, lock scope and parser evidence even with zero packages.
An ignored npm input retains npm dispatch with unknown enumeration. Unsupported
Maven input remains visible with unknown enumeration and ownership.

Indexed input rows preserve the new scalar outcomes and exact detail. Context
links carry the input's immutable identity, context identity/kind and ecosystem,
so account-scoped readers can query root/ecosystem outcomes without reading SBOMs.
The platform must preserve these producer assertions rather than infer them
from occurrence counts or global fidelity.

Earlier producers omit the added fields. Their ecosystem and input enumeration
remain unknown, and their canonical bytes round-trip unchanged. The new reader
accepts those bytes; an earlier reader refuses the added outcome fields. A
runtime must select the matching pinned validator and image payload map before
admitting the new producer. Rollback keeps existing additive rows/artifacts and
must retain the originally selected validator for accepted handoffs.

The 64 source-authored corpus cases retain their original package, version,
edge and ownership expectations. Their 74 recognized input expectations are
extended only with the documented dispatch map and existing parser dispositions.
This additive expectation update is separate from the original pre-execution
package/graph adjudication. New tests independently cover ignored/unsupported
zero-package inputs, separate evidenced roots, invalid domain claims and older
canonical byte compatibility.
