# M046 S04 acceptance ledger

Status: S04 is open. The export, matching, import and identity work is
implemented and has local and hosted executable evidence; native resource
acceptance remains open and is the only S04 acceptance item still open.
S03, which S04 depends on, is complete: issue 91 is closed and its adapters
are on `main`.

Tracking: [S04 #92](https://github.com/sourcebastion/sourcebastion-scanner/issues/92).
Canonical scope: [M046 #88](https://github.com/sourcebastion/sourcebastion-scanner/issues/88).

This file records what the slice establishes and what it does not. It is not a
release, deployment or milestone closure, and it claims no product-route
acceptance.

## What S04 asks for, and where each part stands

| S04 requirement | State | Evidence |
| --- | --- | --- |
| Validated CycloneDX from the local inventory, pinned and consumer-compatible | implemented | [`docs/inventory-cyclonedx.md`](inventory-cyclonedx.md); offline validation against the pinned official 1.6 schemas in `evaluation/m046/cyclonedx-schemas` |
| Purls, evidenced relationships, source/environment identity, provenance, explicit coverage and fidelity preserved | implemented | `tests/test_inventory_cyclonedx.py`; canonical inventory stays authoritative and separately bound by SHA-256 |
| SPDX export, additive, with losses documented rather than equivalence claimed | **not implemented, by choice** | S04 makes it additive; no SPDX engine is selected, and no SPDX artifact is emitted or claimed anywhere. Nothing to document losses against yet |
| Real Grype binary against the verified advisory snapshot | implemented | [`docs/inventory-real-grype-proof.md`](inventory-real-grype-proof.md); native AMD64 and ARM64 hosted smoke jobs in `.github/workflows/docker.yml` |
| SBOM/export status separate from matching status; a valid inventory survives matching failure | implemented, merged | `inventory.direct_pipeline`; `tests/test_inventory_direct_pipeline.py`; [#151](https://github.com/sourcebastion/sourcebastion-scanner/pull/151) |
| Finding identity, severity, deduplication and source locations preserved | implemented | `inventory.matching.recover`; exact artifact IDs, never joined by name or purl |
| Bounded schema/size/path handling and optional import of local build SBOMs | implemented, merged | [`docs/inventory-imported-sbom.md`](inventory-imported-sbom.md); `inventory.imported_sbom`; [#150](https://github.com/sourcebastion/sourcebastion-scanner/pull/150) |
| Imported artifacts cannot silently replace discovery | implemented, merged | `project` holds no composed inventory; a real `uv.lock` composition and an import of the same purl stay two occurrences |
| No scan-time registry downloads, dependency installs or project execution | implemented, merged | `tests/test_inventory_network_denied_equivalence.py`; [#147](https://github.com/sourcebastion/sourcebastion-scanner/pull/147) |
| Engine/config/registry identity in result provenance, with the advisory snapshot | implemented, merged | the receipt's `producer` and `matching_identity`; [#151](https://github.com/sourcebastion/sourcebastion-scanner/pull/151) |
| M036 cache/baseline compatibility keys bound to inventory semantics | implemented, merged | platform `incremental_compatibility.INVENTORY_IDENTITY_FIELDS` and `scanner_identity.INVENTORY_IDENTITY_FEATURE`; platform [#402](https://github.com/sourcebastion/sourcebastion-platform/pull/402) |
| Native resource acceptance | **open** | needs hosted jobs; see below |
| S03 dependency | satisfied | [S03 #91](https://github.com/sourcebastion/sourcebastion-scanner/issues/91) closed; [#148](https://github.com/sourcebastion/sourcebastion-scanner/pull/148) and [#149](https://github.com/sourcebastion/sourcebastion-scanner/pull/149) merged |

Every implemented row above is on `main` as of 2026-10-09:
[#147](https://github.com/sourcebastion/sourcebastion-scanner/pull/147)
(network-denied equivalence),
[#150](https://github.com/sourcebastion/sourcebastion-scanner/pull/150)
(imported-SBOM gate and projection) and
[#151](https://github.com/sourcebastion/sourcebastion-scanner/pull/151)
(pipeline matching and advisory-snapshot provenance) on scanner `main`, and
[platform #402](https://github.com/sourcebastion/sourcebastion-platform/pull/402)
(compatibility keys) on platform `main`.

What remains open is open for reasons no merge addresses: native resource
acceptance needs the hosted jobs, SPDX export is unexercised by choice, and
S04 depends on S03.

## Executable evidence held locally

Run from the scanner checkout:

```sh
rtk proxy .venv/bin/python -m pytest tests/ -k inventory -q
```

This host has **105 pre-existing failures** unrelated to S04: npm, yarn and
pnpm composition and the vendored Node helper expectations, across six files,
plus the Go-binding errors. Re-measured on `main` after S03 merged: the same
105, in the same six files, with 1,398 passing. They fail on pristine `main`. Every S04 change in
this ledger was measured against that baseline immediately before and after,
and the failure set was identical each time; the only delta was the new tests
passing.

## Separation of statuses

The receipt reports `inventory_state`, per-stage `stages`, `matching` and
`matching_identity` independently. A matcher that refuses, times out or returns
a report this inventory cannot account for leaves the composed inventory and
the exported SBOM exactly as they are: `matching` reads `failed`, `reason`
stays null, and the pipeline finalizes. An incomplete inventory and a failed
match are therefore separately visible, which is the property S04 asks for
rather than a description of one.

## Identity

Result provenance carries the composition engine's code digest, its format
registry digest and its discovery configuration digest through `producer`, and
the consumer's binary, config and version together with the advisory
snapshot's digest, schema and build through `matching_identity`. The latter
also carries `recover`'s joint digest over the inventory, the exported SBOM,
the consumer output and the consumer, so none of the four can be swapped under
the others. The three artifact digests are not repeated there; the artifact
facts already carry them.

A failed or absent match records no identity. The consumer is a controller
assertion, and recording it after a failure would read as provenance for
advisories never established against this inventory.

On the platform side, `INVENTORY_IDENTITY_FIELDS` extends a Grype component's
compatibility key with the inventory engine, registry and configuration
digests, admitted only for a scanner declaring the `local-inventory-v1`
feature. Changing inventory semantics therefore invalidates reuse built
without them rather than silently reusing it.

## Imported build SBOMs

`imported_sbom.admit` is the gate and produces no occurrences.
`imported_sbom.project` builds them, carrying `evidence_kind="imported"` and an
`imported-sbom-input` analysis scope naming the admitted document. Both
contract literals widen additively; nothing in the engine branches on either
field.

An import never merges into discovery, and that is a property of the shape:
`project` holds no composed inventory to merge into. Where a component's purl
and its `name`/`version` fields disagree, neither is adopted and the row is
skipped and counted, so an import cannot assert a version its own bytes
contradict. A component restating one already projected is collapsed, because
the canonical model refuses duplicate record ids. Skips and duplicates are
counted separately and never summed: one says the model could not state a
component, the other says it was already stated.

Relationships are not projected, and no route invokes the module. The identity
rule above is defined for imports and not yet enforced for them: no imported
identity reaches result provenance or the compatibility inputs.

## SPDX

S04 makes SPDX export additive and conditional: permitted only if the selected
engine preserves the canonical contract, and required to document its losses
rather than claim equivalence with CycloneDX. No engine has been selected, no
SPDX artifact is emitted, and no SPDX capability is advertised. The condition
is therefore unmet and the requirement unexercised, which is a different thing
from being satisfied. Any future SPDX path owes a loss table before it is
offered as an alternative to the CycloneDX export.

## What this does not establish

Native resource acceptance is open and cannot be closed from a developer
checkout: aggregate CPU-time enforcement, complete kernel traces, same-UID
administrator fencing and AMD64/ARM64 resource behaviour need the hosted jobs.
The real-Grype proof is a finite integration proof and says so itself.

Also open: production controller custody, advisory database publisher
signatures, whole-milestone acceptance, and release or deployment readiness.
Findings may be compared across architectures only under equal advisory
snapshot identity.

S04's dependency on S03 is satisfied:
[issue 91](https://github.com/sourcebastion/sourcebastion-scanner/issues/91)
is closed and its ecosystem adapters are on `main`. That removes the
dependency, not the open native gate above. This ledger is a record of S04's
state, not a claim that S04 is accepted.
