# M048 S01: `sourcebastion.inventory/2` license evidence

Slice S01 of [M048](M048-scope.md) ([#175](https://github.com/sourcebastion/sourcebastion-scanner/issues/175)). This slice adds license evidence to the canonical contract
in `sourcebastion.inventory.contract`, with a [structural schema
snapshot](M048-inventory-v2.schema.json). The M046 `/1` snapshot is kept as
history. No adapter emits license evidence yet; S03 does that.

## Records

`LicenseObservation` is one located license claim about one occurrence:

| Field | Meaning |
|---|---|
| `occurrence_id` | The occurrence the claim is about. It must exist. |
| `source` | Locator of the read input that states it, bound to coverage like every other record |
| `evidence` | `declared-manifest`, `package-metadata`, `lock-record`, `provider` or `imported-claim` |
| `value_raw` | The stated value, bounded (16 KiB) and control-free |
| `expression` | Canonical SPDX expression, or null |
| `parse` | `canonical`, `deprecated`, `licenseref` or `unparsed` |

`expression` and `parse` must be what the pinned SPDX list
(`packaging==26.3`, list 3.27.0) makes of `value_raw`. A producer cannot assert
an identifier its own raw value does not yield, hide a parseable value as
unparsed, or hide a deprecation.

`LicenseGap` records that no input the producer read states a license for an
occurrence, with a stable reason code. A gap is not an observed `NOASSERTION`
or `NONE`: those are claims and are recorded as unparsed observations.

## Rules enforced by the contract

- **Every occurrence is assessed.** Each occurrence has one or more
  observations or exactly one gap, never both and never neither. A `/2`
  inventory therefore cannot read as license-clean by omission.
- **Conflicts are retained.** Several observations for one occurrence, even
  with different evidence kinds or values, are all kept. Policy (S04) evaluates
  the strictest. The contract doesn't merge or rank them.
- **Imported claims stay imported.** `imported-claim` observations attach only
  to `imported` occurrences, and imported occurrences carry only imported
  claims.
- **Provider claims need a provider reference.** A `provider` observation
  requires the occurrence to carry a provider reference. The provider never
  creates occurrences.
- **No inference.** The contract has no field for a guessed, looked-up or
  name-derived license.

## Versions

`Inventory.schema_version` accepts `sourcebastion.inventory/1` and
`sourcebastion.inventory/2`. The default stays `/1` until producers emit
license evidence.

- **`/1`** carries no license fields. Its canonical bytes are exactly what
  M046 producers emitted, so existing digests, recovery identities and stored
  artifacts are unchanged. A `/1` record with any license field is refused,
  and so are `/1` bytes with injected license keys (they are noncanonical).
- **`/2`** requires `license_list_version` to equal the pinned list version.
  Canonical bytes sort `licenses` and `license_gaps` by ID.

The canonical reader accepts both versions explicitly. `summary_projection`
reports the version it read instead of assuming `/1`.

## Compatibility identity

`license_list_version` is inside the `/2` canonical bytes, so the inventory
digest, and every identity built on it (`recover`'s joint digest, artifact
facts), changes with the SPDX list. An inventory parsed under another list
version is refused rather than reinterpreted.

Before any producer emits `/2` (S03), the platform must accept `/2`, and its
`INVENTORY_IDENTITY_FIELDS` compatibility key must include the license-list
version so cached results built under another list aren't reused. That
platform change is tracked with S04 and S06. Until then, producers keep
emitting `/1`.
