# Imported local build SBOM handling

This defines how a source- or artifact-bound local build SBOM may be admitted.
Nothing implements it yet: `inventory.cyclonedx` exports and does not accept an
imported BOM, and no general imported-BOM validator exists. The definition is
written first because the constraints decide the shape, and because an importer
that is designed after the fact tends to acquire the one property this slice
forbids.

## The constraint that drives the rest

An imported artifact never silently replaces discovery. Local composition stays
authoritative: an import is additional evidence with its own provenance, not a
substitute inventory. A build SBOM describes what a build produced, which is a
different question from what the source declares, and the two disagreeing is
information rather than a conflict to resolve. An import therefore cannot
remove, renumber or re-identify a discovered occurrence, and cannot promote
inventory coverage: `discovery` and `enumeration` keep the states composition
gave them.

Import is optional in every sense. No route requires one, absence is not a
coverage gap, and admitting one must not introduce mandatory forge or CI access
to obtain it. An SBOM reachable only by calling a forge API is out of scope
here; the artifact must already be present in the admitted source or supplied
by the controller as explicit bytes.

## Bounds

Schema: an allowlisted specification and version only, matching the exported
profile's pinned set. An unrecognised `bomFormat`, `specVersion` or schema
identity refuses; there is no best-effort parse and no version coercion.

Size: the imported bytes carry their own cap, separate from the export cap, and
are read through the existing bounded JSON reader so ambiguous or oversized
syntax refuses before any schema work. Duplicate keys, nonfinite numbers and
unbounded depth refuse as they do elsewhere. No silent truncation: a document
above the cap is refused atomically, with no partial admission.

Path: an artifact named inside the source is resolved exactly as every other
input is. `inputs.relative_path` refuses an absolute path, a `..` component, a
backslash, a NUL and anything over 4096 bytes; `inputs.Source` opens relative
to the pinned root descriptor without following symlinks and re-checks the
root's identity as it walks. An import gets no weaker rule than a manifest, and
no second path implementation. An artifact supplied as bytes carries no path
and is identified by digest alone.

Identity: an admitted import records its own sha256, its declared
specification, and the source or controller binding it arrived under. That
identity belongs in result provenance and in the M046 compatibility inputs for
the same reason the composition engine does — an import that changes what the
component can find must invalidate reuse built without it.

## What an admitted import may do

It may add occurrences that discovery did not reach, each marked with its own
evidence kind and the import's identity, so a reader can tell a declared
dependency from a built one. It may carry relationships, which stay separate
from evidenced local relationships rather than merging into them. It may
contribute coverage inputs describing itself.

It may not merge by name or purl into a discovered occurrence. Equal purls from
an import and from composition remain separate occurrences, as equal purls from
different contexts already do. Joining them would assert that the built
artifact and the declared dependency are the same thing, which the bytes do not
establish.

## What is implemented

`inventory.imported_sbom.admit` is the gate: bounded decode, allowlisted
`CycloneDX` / `1.6` with no version coercion, a component ceiling, an 8 MiB
import cap separate from the export cap, and `inputs.relative_path` for a
source-bound artifact. It returns an `ImportedBom` -- digest, specification,
component count and binding -- and charges the caller's ledger.

It opens no file: a caller reading from source does so through `inputs.Source`,
which refuses symlinks against a pinned root descriptor, and passes the bytes.

## What this does not establish

Admission produces no occurrences. Projecting an imported component into the
canonical model is a separate question with its own evidence rules -- the
no-merge-by-purl constraint above is the hard part, not the parsing -- and
answering it inside the gate would give the gate the property this slice
forbids. No route invokes the module, and nothing writes an imported
identity into result provenance or the compatibility inputs yet.

The export, matching and real-Grype proofs are unchanged. Native resource
acceptance remains open.
