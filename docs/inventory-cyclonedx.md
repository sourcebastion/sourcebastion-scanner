# Canonical local CycloneDX export

The internal exporter consumes a revalidated canonical Inventory and emits a fixed flat CycloneDX1.6 profile. It does not rescan a repository or accept an imported BOM. The canonical inventory remains authoritative and separately bound by SHA256. Exact selected occurrences retain their canonical occurrence IDs, purls and source locations; equal purls from different contexts remain separate. Versionless occurrences and declarations remain metadata, with explicit projection counts.

Only evidenced active unconditional relationships between selected components enter standard dependencies. Conditional, inactive, unknown or unassessed relationships remain in typed metadata and explicit projection losses. Missing dependency arrays do not assert dependency absence. Compositions remain unknown. CycloneDX defaults omitted component scope to required at runtime; that default is unassessed here, not a claim of installation or reachability. Every component records an explicit default-required scope projection loss, counted in the receipt and metadata. Consumers must use canonical scopes and activation; unknown cannot be mapped to optional or excluded without evidence. Coverage, original stage states, environment, source and producer identities remain visible; successful export changes neither inventory completeness nor matching status.

The runtime admits only this generated profile from the typed canonical contract. Separate offline gates validate actual installed/native emitted artifacts against the pinned official CycloneDX1.6 schemas in evaluation/m046/cyclonedx-schemas. These are unchanged files from specification commit55343ba19dee1785acf1ce9191540d5fd7b590db, with upstream license and SHA receipts. Official JSON Schema tools are test/diagnostic dependencies, not scanner runtime dependencies or remote schema resolvers. There is no general imported-BOM validator here.

The trusted host validator pins all six packages, including typing-extensions4.16.0 required transitively on the CI host. Preparation downloads only the explicitly pinned wheels; installation resolves solely from that offline wheel directory and fails if another dependency is needed. The gate checks and records all six installed versions. Retained host wheels belong to the actual host Python/platform, separately from the scanner producer's Python3.14.8/Alpine execution. Earlier evidence with five direct pins and an unpinned sixth package does not qualify this corrected closure.

The caller supplies the remaining shared deadline and semantic ledger, plus the outer kernel resource boundary. Canonical preflight precedes copying; generated values have the frozen node/depth/string caps, and output is buffered with the SBOM byte cap. Any refusal emits no artifact. A metadata property above2MiB is refused atomically; no silent truncation or false export success occurs. The eight native export fixtures use Source.check for the source deadline and epoch; they do not establish a shared semantic counter across all stages. Whole-pipeline ledger and resource acceptance remain open.

The artifact identity includes exact canonical bytes, source/producer/environment, exporter and schema identities. Matching/config/advisory identities and M036 integration remain a later gate. Real Grype matching and source recovery, production routing, richer corpus acceptance and M046 completion are not established by the eight finite native exports.

## License evidence (M048 S05)

An `inventory/2` export carries license evidence. An `inventory/1` export is
byte-identical to before.

- **One expression:** when every observation for a component yields the same
  canonical expression, the component declares it as
  `licenses: [{"expression": E, "acknowledgement": "declared"}]`. The
  expression form is used even for a single identifier, because the pinned
  SPDX list (3.27.0) has identifiers that CycloneDX 1.6's `license.id`
  enumeration lacks. A `license.id` for those would fail schema validation.
- **Anything else** (unstated, unparsed, or conflicting observations) gets no
  `licenses` field. This avoids flattening or choosing between claims, and the
  component records the `license-evidence-not-representable` projection loss.
- **Properties:** every observation is retained as a
  `sourcebastion:inventory:license-observation` component property, and a gap
  as `license-gap`. The metadata records `license-list-version`.

The export still contains no timestamp. License data reaches
`identity_sha256` only through the inventory digest, so it stays
byte-reproducible.

No SPDX document is emitted (M048 D2).
