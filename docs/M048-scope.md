# M048 scope: license scanning and compliance

Scoping record for [#154](https://github.com/sourcebastion/sourcebastion-scanner/issues/154).
It decides the authoritative license source and whether SPDX output is needed,
and it lists numbered slices with their dependencies on the M046 canonical
contract. No implementation is merged under #154. Status: **accepted**. The
owner signed off D1–D8 on 2026-10-11. D8 records the owner's answers to the
open questions.

Surveyed at `main` 7052913.

## Current state

PLAN-11 is marked shipped in `ROADMAP.md`. What exists today:

- `sourcebastion/license_checker.py` runs the `syft` **CLI** found on `PATH`
  (`syft dir:<path> -o json`), reads `artifacts[].licenses`, and matches each
  string with `fnmatch` against `license_policy` lists in `.sourcebastion.yaml`.
  It runs only when `scan --license-check` is passed and a policy is configured.
- `images/Dockerfile` copies `gitleaks` and `grype` into the runtime image. It
  does **not** ship a `syft` binary. Grype embeds Syft as a library but exposes no
  `syft` command. ROADMAP's "Syft (bundled with grype)" is therefore wrong for the
  published image: with a license policy configured, `--license-check` raises
  `ScannerExecutionError("license-checker", "not_installed")` there.
- When a `syft` binary is present, its version is unpinned and its defaults are
  not the offline profile. That is a different Syft from the pinned 1.54.0
  restricted provider (`docs/inventory-provider.md`), whose profile *refuses*
  remote, Go module cache and vendor license lookup.
- The canonical inventory (`sourcebastion.inventory/1`) carries no license
  fields. `python_metadata.py` budgets `License-Expression` before validation,
  but the value is not retained.
- The runtime closure already pins `packaging==26.3`
  (`scripts/python-runtime.in`), which ships `packaging.licenses` and SPDX
  license list **3.27.0**.

Defects in the current policy, reproduced on 7052913:

| Policy | Input | Result | Problem |
|---|---|---|---|
| `denied: [GPL*]` | `MIT AND GPL-3.0-only` | `allowed` | The pattern is matched against the whole expression string, so a conjunctive GPL term escapes. |
| `denied: [AGPL*]` (deny-only) | `NOASSERTION` | `allowed` | With a deny-only policy, anything not denied counts as permitted, including "no assertion". |
| `allowed: [MIT]` | `MIT OR GPL-3.0-only` | `unknown` | The user can choose MIT here, but the policy doesn't model choice. |
| any | `Foo` (not SPDX) | matched as text | A non-SPDX string is matched as a pattern instead of being refused as unrecognised. |

## Decisions

### D1. Authoritative source: the canonical inventory, and only the canonical inventory

License data enters as **evidence on canonical occurrences**, produced by the
same adapters that already read the files where licenses are declared. The
`syft` CLI route is retired, not kept as a parallel source.

Reasons:

- Two sources with no precedence is the state #154 rejects. Any precedence rule
  between them would still have to reconcile occurrences, and only the canonical
  inventory has occurrence identity, roots, environments and coverage.
- The CLI route can't run in the published image, and where it does run it's
  unpinned and may reach the network. Fixing it would mean shipping and pinning
  a second Syft alongside the restricted provider.
- Coverage and completeness semantics already exist in the inventory. A license
  policy evaluated over a partial inventory must say so. Syft output has no such
  notion.

The restricted provider stays a *supporting* producer. Where its pinned offline
profile reports a license for an occurrence it already binds, that becomes a
`provider` evidence kind on that occurrence. It never creates occurrences and
never overrides a manifest or metadata observation.

### D2. SPDX document output: not needed; PLAN-10's out-of-scope line stands

Nothing is built. Reasons:

- SPDX 2.3 requires `creationInfo.created`. The emitted CycloneDX omits
  timestamps so `identity_sha256` is byte-reproducible. Emitting SPDX means
  either a second, non-reproducible artifact or a fake fixed timestamp. Neither
  is acceptable.
- `imported_sbom.py` admits CycloneDX 1.6 only, so that one schema family is
  reasoned about. Emitting SPDX without importing it would be asymmetric, and
  importing it doubles the import surface.
- CycloneDX 1.6 carries what licensing needs: `licenses[].expression` and
  `licenses[].license.id` take SPDX expressions and identifiers. The SPDX
  *license list* is the vocabulary (D4). The SPDX *document format* isn't needed
  to use it.
- No customer, auditor or regulatory requirement for SPDX specifically is on
  record. EO 14028 / NTIA minimum elements accept CycloneDX.

**Revisit trigger:** a named customer or regulation that requires an SPDX
document. Record the requirement in a new issue. Don't reopen this one.

### D3. Expressions are parsed, not pattern-matched

Every license value is canonicalized with the pinned
`packaging.licenses.canonicalize_license_expression` and then evaluated
structurally:

- `A OR B`: permitted if **any** branch is permitted, and denied only if every
  branch is denied. The finding names the branch that satisfies the policy.
- `A AND B`: permitted only if **every** term is permitted. Denied if any term is
  denied.
- `X WITH E`: a single term. Policy entries can name `X` (any exception) or
  `X WITH E` exactly. An exception never turns a denied `X` into a permitted one
  unless the policy names that exact pair.
- `LicenseRef-*`: a valid but unrecognised term. It's undetermined unless the
  policy names it exactly.
- A value that doesn't canonicalize (free text such as `BSD-like` or
  `see LICENSE`) is kept verbatim as `unparsed`, and its policy result is
  undetermined. It's never guessed into an identifier.

Wildcards remain, but they apply to **individual identifiers after parsing**
(`GPL-*` matches the `GPL-3.0-only` term), never to the raw string. The policy
config validator refuses patterns that contain operators.

Deprecated identifiers (`GPL-2.0+`) are accepted as the list allows and are
reported as deprecated. They aren't rewritten to their replacements.

### D4. Pinned vocabulary is a compatibility-key input

The SPDX license-list version (3.27.0 via `packaging==26.3`) is recorded in
result provenance and joins the inventory compatibility identity, the same way
the advisory snapshot does in M046 S04. Upgrading `packaging` changes what a
policy can recognise, so it invalidates cached license results. A second,
independent SPDX list isn't introduced.

### D5. Policy semantics

Every evaluated occurrence gets exactly one result: `permitted`, `denied` or
`undetermined`.

- **Undetermined is never permitted**, under any policy shape. That fixes the
  deny-only `NOASSERTION` defect. Undetermined covers: no license observed,
  `NOASSERTION`, `NONE` as declared, `unparsed`, unlisted `LicenseRef-*`, and
  terms that neither list names when an allow list exists.
- In a deny-only policy, an SPDX term that isn't denied is permitted.
  Undetermined values are still reported.
- A denial is a **finding** (`category: license_compliance`, unchanged), and it
  gates only through the existing severity/baseline gate. There's no separate
  license gate. Defaults: denied = `high` and undetermined = `medium`, as today.
  Undetermined severity is configurable down to `low` but can't be suppressed
  globally. Suppression stays per `rule_id` through ignore rules.
- `rule_id` is derived from the **canonical** expression, not the raw string, so
  `mit` and `MIT` produce one rule. This changes existing rule IDs. S04 ships a
  migration note only, and old-form IDs are not accepted (D8).
- Findings bind occurrence ID and evidence location (manifest path and line, or
  metadata file), replacing today's `file: "dependency: <name>", line: 0`.
- When license coverage is partial, the summary says so. "0 denied" over a
  partial inventory never renders as "compliant".

### D6. Evidence rules for license observations

Each license observation records:

- `value_raw` (bounded and control-free, per the existing metadata field budget)
- `expression` (canonical, or null)
- `parse`: `canonical`, `deprecated`, `licenseref` or `unparsed`
- `source`: `declared-manifest`, `package-metadata`, `lock-record`, `provider`
  or `imported-claim`
- the bound source path and SHA-256 (via existing coverage)

Rules:

- **No inference from package name**, registry lookup or network. If no file
  observed by the adapter states a license, the observation is `unobserved`,
  with a reason code (for example `ecosystem-lock-carries-no-license`).
- A declared license in a source manifest is the project's *claim* about
  itself. A license in installed package metadata is the published package's
  claim. Neither is the license of a built artifact. The record keeps `source`
  so consumers can tell them apart, and nothing merges them.
- Conflicting observations for one occurrence are all kept, and policy evaluates
  the **strictest**: any denied observation means denied, and any undetermined
  observation means not permitted. Conflicts are reported.
- Imported CycloneDX `licenses` are `imported-claim` observations under the
  rules the imported-SBOM work already applies to other imported fields.

Expected per-ecosystem availability for S03, to be confirmed by each adapter:

| Ecosystem | Offline license evidence in files the adapter already reads |
|---|---|
| npm / pnpm / yarn | `package-lock.json` v2+/v3 `packages[*].license`; `package.json` `license`; pnpm/yarn locks: none expected |
| Python | installed `METADATA` `License-Expression` (PEP 639), then `License` and classifiers as `unparsed`; `pyproject.toml` `project.license` for the root |
| Composer | `composer.lock` `packages[*].license` (array, read as OR) |
| Maven / Gradle | `pom.xml` `<licenses>` for the root only; Gradle locks: none |
| Cargo / Go / NuGet / Bundler | locks carry none, so `unobserved` with a reason, unless the provider binds one offline |

### D7. Platform surface: extend M047, no new tab

License data appears in M047's **Dependencies** tab (S04 of
[platform#377](https://github.com/sourcebastion/sourcebastion-platform/issues/377)):

- a license column and a `permitted / denied / undetermined` filter
- per-package evidence in the details view

License findings appear with other findings, filtered by
`category: license_compliance`. A breakdown by license is a summary card on the
Dependencies tab and doesn't get its own tab. Implementation is a
platform-repo issue that depends on M047 S04 and M048 S01. This document only
names it.

## Slices

| Slice | Deliverable | Depends on |
|---|---|---|
| S01 | Contract: `sourcebastion.inventory/2` with license-observation records, evidence kinds and `unobserved` reasons (D8), the `/1` → `/2` reader and export transition, and compatibility-key additions | M046 canonical contract (`docs/M046-canonical-contract.md`) |
| S02 | Expression evaluator over the pinned `packaging` canonicalizer; identifier-scoped wildcards; config validator refusing operator patterns; property tests on OR/AND/WITH/LicenseRef/unparsed | D3, D5; independent of S01, can start immediately |
| S03 | Adapter observations: npm/pnpm/yarn, Python metadata and pyproject, Composer, Maven root; explicit `unobserved` for Cargo/Go/NuGet/Bundler; provider license binding under the existing offline profile | S01; each M046 adapter as merged |
| S04 | Policy over the canonical inventory: findings with occurrence and location binding, canonical `rule_id`, coverage-aware summary, `rule_id` migration note; **remove** the `syft` CLI route and its interim refusal (D8) | S02, S03 |
| S05 | CycloneDX export of license evidence (`licenses[].expression`); imported-SBOM `licenses` read as `imported-claim`; reproducibility proof that `identity_sha256` stays byte-stable | S01, S03; M046 S04 export and import |
| S06 | Platform: Dependencies-tab license column, filter and evidence; finding category filter (platform-repo issue) | S04, S05; platform M047 S04 |
| S07 | Acceptance: corpus covering each ecosystem row in D6, compound and conflicting expressions, partial coverage, deny-only and allow-list policies, vocabulary-upgrade invalidation; published-image run | S01–S06 |

S01 and S02 can start now and run in parallel. S04 is the first
slice that changes user-visible behaviour.

## Out of scope

License text extraction, OSI/FSF approval lookup, license compatibility
reasoning between packages, obligation and attribution tooling, SBOM signing,
SPDX document output (D2), any network enrichment, and release or deployment
commitments. PLAN-11's existing out-of-scope list carries over. Distribution
obligations for *our own* image are [M049](https://github.com/sourcebastion/sourcebastion-scanner/issues/164), not M048.

## D8. Owner answers (2026-10-11)

1. **Interim `--license-check`.** It now fails clearly instead of failing late,
   in a fix outside M048 (branch `fix/license-check-requires-syft`). With a
   `license_policy` configured and no `syft` on `PATH`, `scan --license-check`
   exits 1 before any scanner runs, and the message names the missing command,
   the published image and this milestone. The docs no longer claim syft is
   bundled with grype. S04 removes the refusal along with the route.
2. **Schema.** License evidence goes into a bumped `sourcebastion.inventory/2`,
   not a sibling record. S01 owns the version transition: the `/2` schema
   snapshot, readers that refuse or explicitly accept `/1`, and the
   compatibility-key change that the bump implies.
3. **`rule_id` change.** A migration note is enough. Existing license ignore
   rules that use raw-string IDs stop matching, and S04 documents the mapping.
   No dual-form acceptance is built.
