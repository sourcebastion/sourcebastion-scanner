# M048 S03: license observations from inputs already read

Slice S03 of [M048](M048-scope.md) ([#177](https://github.com/sourcebastion/sourcebastion-scanner/issues/177)). Adapters record the license value an
input they already read states, as `inventory/2` evidence
([S01](M048-inventory-v2.md)). Nothing is looked up, fetched or inferred from
a package name.

Composition emits `/2` only when called with `licenses=True`
(`compose_source(..., licenses=True)`). Without it, output stays `/1` and
byte-identical. S04 turns it on in the scan route once the platform reads `/2`.

## What each adapter records

| Ecosystem / input | Evidence | Recorded as |
|---|---|---|
| npm `package-lock.json` v2/v3 | `packages[<entry>].license` | `lock-record` at `/packages/<entry>/license`. A string is the claim. A legacy object such as `{"type": "MIT"}` is kept as compact JSON and is unparsed. |
| Composer `composer.lock` | `packages[i].license` | `lock-record` at `/packages/<i>/license`. Composer defines the array as disjunctive, so members join with `OR`, and a member that is itself an expression is parenthesized. An empty array states nothing. |
| Python installed `METADATA` | `License-Expression` (PEP 639) | `package-metadata`. When present it is the only claim, because it supersedes the rest. |
|  | otherwise `License` | One unparsed claim, unless the value is `UNKNOWN` (the setuptools default), which states nothing. |
|  | otherwise `License ::` classifiers | One unparsed claim per classifier |
| pnpm, Yarn, Cargo, Go, NuGet, Bundler, Gradle, Maven, Python source declarations and locks | none in the inputs read | A gap: `<ecosystem>-<evidence>-input-states-no-license` |

Every occurrence ends up with observations or exactly one gap, as `/2`
requires.

Whitespace runs in a stated string collapse to single spaces, because the
contract refuses control characters and folded metadata headers carry
newlines. Values over 16 KiB state nothing usable and become gaps rather than
truncated claims.

## Not recorded

- **The project's own license.** The root `package.json`, `pyproject.toml`
  `project.license` and root `pom.xml` `<licenses>` describe the scanned project,
  which has no occurrence. They aren't dependency evidence and aren't
  attached to anything.
- **Provider licenses.** The restricted provider isn't called by the scan route,
  and its offline profile refuses remote, module-cache and vendor license
  lookup. A `provider` observation needs an occurrence with a provider
  reference (S01). When the provider is integrated, it can emit them under that
  rule.
- **Imported SBOM licenses.** These are S05 (`imported-claim`).

## Tests

`tests/test_inventory_license_evidence.py` covers:

- Composer single, dual, absent and non-SPDX licenses
- PEP 639 precedence over classifiers
- legacy `License` and classifier claims
- the `UNKNOWN` default becoming a gap
- npm string and legacy-object licenses
- an every-occurrence assessment across mixed ecosystems
- deterministic bytes
- `/1` output without the flag

The npm composition case needs the Linux selector runtime, so it skips when
that runtime is unavailable. The npm parser case runs everywhere.
