# M048 acceptance ledger

Slice S07 of [M048](M048-scope.md) ([#180](https://github.com/sourcebastion/sourcebastion-scanner/issues/180)). This ledger binds each scope
decision to its implementation and to the evidence that it holds. It records
what was observed and what remains open.

Status: **implemented on unmerged branches. Local-image acceptance passes, and
published-image acceptance is pending a release.**

## Implementation

| Slice | Repository | Commits |
|---|---|---|
| S02 expression evaluator ([#176](https://github.com/sourcebastion/sourcebastion-scanner/issues/176)) | scanner | `3369595` |
| S01 `inventory/2` contract ([#175](https://github.com/sourcebastion/sourcebastion-scanner/issues/175)) | scanner | `6af5fb9` |
| S03 license observations ([#177](https://github.com/sourcebastion/sourcebastion-scanner/issues/177)) | scanner | `10bbe69` |
| S04 policy over the inventory ([#178](https://github.com/sourcebastion/sourcebastion-scanner/issues/178)) | scanner | `bc8cbfa`, `90f5ad2`, `27e4abe` |
| S05 CycloneDX export and import ([#179](https://github.com/sourcebastion/sourcebastion-scanner/issues/179)) | scanner | `d94d79c` |
| S06 row projection ([platform#421](https://github.com/sourcebastion/sourcebastion-platform/issues/421)) | scanner | `42cfd0e` |
| S06 storage, compatibility key and Dependencies tab | platform | `97c3203`, `57fa00b`, `85623bc` |
| S07 corpus, expectations and verifier | scanner | this commit |

## Decisions and evidence

| Decision | Holds because | Evidence |
|---|---|---|
| D1: the canonical inventory is the only license source | `license_checker` composes `inventory/2` and never runs `syft`. A subprocess guard in the tests proves no tool is executed. | `tests/test_license_checker.py::test_no_syft_is_ever_executed`; the local-image run below has no `syft` binary |
| D2: no SPDX document output | Only CycloneDX is emitted. Exports stay timestamp-free and byte-reproducible with license data. | `tests/test_inventory_cyclonedx_licenses.py::test_identity_is_byte_reproducible_with_license_data` |
| D3: expressions are parsed | `OR`/`AND`/`WITH`, `LicenseRef-*` and unparsed values are evaluated per term. The four defects recorded on `main` 7052913 are regression tests. | `tests/test_license_expression.py::TestRecordedDefects`; corpus rows `left`, `right`, `classpath`, `acme/ref`, `legacy` |
| D4: the pinned list is a compatibility input | `/2` binds `license_list_version` in its canonical bytes and refuses another version. The platform requires `inventory_license_list_version` under `local-inventory-licenses-v1`. | `tests/test_inventory_license_contract.py::test_license_list_version_is_pinned`; platform `tests/test_scanner_identity.py::test_a_license_inventory_must_pin_its_license_list_version` |
| D5: undetermined is never permitted | Unstated, unparsed, unlisted `LicenseRef` and off-list values are undetermined under every policy shape, including deny-only. | corpus rows `acme/silent`, `acme/proprietary`, `bare`, `unknowndefault`, `acme-gem`; `test_deny_only_policy_still_reports_unstated` |
| D6: evidence rules | Every `/2` occurrence has observations or exactly one gap. Conflicts are retained, and nothing is inferred. Imported claims stay on imported occurrences. | `tests/test_inventory_license_contract.py`, `tests/test_inventory_license_evidence.py` |
| D7: platform surface in the Dependencies tab | The tab shows the stated expression or evidence state, a whole-snapshot breakdown, a filter by state, and per-observation evidence. | platform `tests/test_sbom_license_evidence.py`; ad hoc real-inventory render below |
| D8: owner answers | Interim refusal (#173), now superseded by S04. `inventory/2` with explicit `/1` handling. Rule IDs changed with a migration note only. | `docs/integrations.md` migration notes; `tests/test_inventory_license_contract.py::TestInventoryV1` |

## Acceptance corpus

`evaluation/m048/license-corpus` holds Composer, npm, installed Python
metadata and Bundler inputs, evaluated under
`evaluation/m048/license-policy.yaml`. `evaluation/m048/license-expectations.json`
records each package's expected result and rule ID.

`scripts/verify-m048-license-acceptance.py` composes the corpus offline,
evaluates it and exits non-zero on any mismatch.

### Local image run (2026-10-12)

- **Image:** `sourcebastion-scanner:m048-s07-local`, built from
  `images/Dockerfile` at the S06 scanner commit plus the S04 fix, image ID
  `sha256:292ad8cf…3703`.
- **Command:** run with `--network none`, so the license check is proven
  offline. The report is `evaluation/m048/acceptance-run-local-image.json`.
- **Result:** exit 0, no mismatches. `inventory/2`, coverage `complete`,
  16 resolved packages: 5 permitted, 2 denied, 9 undetermined. 5 declarations
  were not assessed, and the license list is 3.27.0.

Both runs were repeated after the corpus's Bundler fixture changed from the
real `rack@3.1.7`, whose published advisories failed GitHub dependency
review, to a fictional `acme-gem`. Results were identical.

An earlier run found a defect, which was fixed before acceptance. Declared
`package.json` dependencies were reported as "no license stated" beside their
locked packages. `27e4abe` now evaluates only resolved packages and counts
declarations separately.

### Full CLI scan in the local image (2026-10-12)

`sourcebastion scan /scan --license-check` ran in the same image against the
corpus, with the policy as `.sourcebastion.yaml`. Network access was allowed,
because grype fetches its advisory database. There is no `syft` binary in the
image.

- **Result:** exit 0. It reported `16 package(s) - 5 permitted, 2 denied,
  9 undetermined` and the five declarations that weren't license-checked.
- **Findings:** the two denials were `acme/gpl` (`GPL-3.0-only`) and `left`
  (`MIT AND GPL-3.0-only`), and the nine undetermined packages were listed with
  their stated values or "no license stated".
- **Exit status:** exit 0 is the configured behaviour. License findings gate
  only through the existing severity and baseline gate (D5), and this run
  configured none.

### Platform rendering of real rows (2026-10-11)

A real `/2` inventory composed from the corpus went through the scanner row
projection, the platform's inventory row store and the Dependencies tab
route. npm was omitted on macOS for lack of the Linux selector runtime.

- **Shown on the page:** the breakdown, the Composer `MIT OR GPL-3.0-or-later`
  expression, "No license stated", and the `unstated` filter.
- **Package detail:** names `GPL-3.0-only` with `lock-record` at
  `/packages/2/license`.

This was an ad hoc check, run with the S07 scanner on `PYTHONPATH`. It isn't
a committed platform test, because the platform's scanner dependency is still
the released version.

## Open

- **Published-image acceptance.** Requires merging these branches and a
  release. Then rerun the verifier against
  `ghcr.io/sourcebastion/sourcebastion-scanner` and record the digest here.
- **Hosted inventory producer.** It still emits `/1`. Enabling `/2` in the
  hosted pipeline requires these steps:
  1. Merge platform `97c3203`/`57fa00b` (migration 0107 and the compatibility
     identity).
  2. Bump the platform's scanner pin.
  3. Make the scanner identity declare `local-inventory-licenses-v1` with
     `inventory_license_list_version`.
  4. Pass `licenses=True` in the dependency job.
- **Development human acceptance** of the Dependencies-tab license surface
  on a deployed environment.
