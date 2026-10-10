# M046 S07 acceptance ledger

Status: **open**. This ledger records the acceptance requirements and evidence
available on 2026-10-10. No published-image, development or rollback acceptance
is claimed. Tracking: [S07 #94](https://github.com/sourcebastion/sourcebastion-scanner/issues/94);
scope: [M046 #88](https://github.com/sourcebastion/sourcebastion-scanner/issues/88).

## Slice prerequisites

| Slice | Required evidence | Current state |
| --- | --- | --- |
| S01 | Independent corpus, engine decision and frozen numerical ceilings, with reviewed immutable receipts | Accepted by #88; [architecture decision](../evaluation/m046/architecture-decision.md), [independent review](../evaluation/m046/evidence/S01-independent-review.md). Final release must retain this baseline rather than comparing only against its immediately preceding commit. |
| S02 | Content validation, custom paths, exclusions and located discovery outcomes over the independent corpus | Accepted by #88 and [#90](https://github.com/sourcebastion/sourcebastion-scanner/issues/90). Revalidate against the published release. |
| S03 | Selected-version, declaration, occurrence and graph semantics on supported ecosystems; explicit unsupported outcomes | Accepted by #88 and [#91](https://github.com/sourcebastion/sourcebastion-scanner/issues/91). The owner waived legacy scanner parity, not truthful semantics or the minimum corpus. |
| S04 | Standards-valid CycloneDX, actual offline Grype, four pip advisory groups, matching identity and independent failure states | [Acceptance ledger](M046-S04-acceptance.md) records merged implementation and finite native evidence. #92 remains open; reconcile its acceptance record with reviewed evidence. SPDX moved to M048 #154. |
| S05 | Immutable queryable rows, authorized artifact access, truthful root/ecosystem coverage, retention/reuse and development presentation | Foundation #403 merged. [Platform #404](https://github.com/sourcebastion/sourcebastion-platform/pull/404) is draft at `9c6e3a6588ff14603b2d260b9da034c878811ea2`; [scanner #162](https://github.com/sourcebastion/sourcebastion-scanner/pull/162) is draft at `af6e138e709c27ba03f0c716ebb0488d1183f484`. Independent review, reviewed schema changes and integration acceptance remain prerequisites. |
| S06 | Verified native packaging, upgrade gates, numerical budgets, support/runbook, #54 coordination and release evidence | Implementation merged. Native PR run verified below; actual release evidence remains open. [#163](https://github.com/sourcebastion/sourcebastion-scanner/pull/163) proposes distribution deferral to M049; this ledger does not decide that separate proposal. |
| S07 | All preceding slices accepted, published native proof, development human acceptance and rollback/mixed-version receipts | Open; required demonstrations below. |

Issue closure alone is insufficient. Each accepted slice must link its actual
criterion-by-criterion evidence and bind that evidence to the qualifying release
tuple. A later parser/config change requires review and the affected proofs again.

## Native CI evidence independently inspected

Run [38024740699](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/38024740699)
completed successfully at source `3ac1928a013a4687917e43e7cd17659f104d1118`.
The [retained audit](M046/S07/native-ci-audit-38024740699.json) records eight archive
IDs and GitHub SHA-256 digests, all checked against downloaded bytes. It verifies:

- 21 corpus/stress resource receipts plus three installed-entrypoint repeats on
  each architecture, with nonempty workload bytes matching every receipt hash;
- passing budgets, zero swap/OOM kills and owned-container removal in all 48 receipts;
- six installed-entrypoint proof bindings to the control recipe, workload receipt
  and host observation, with the expected advisory groups present;
- all 64 canonical corpus case digests equal across native AMD64 and ARM64, with
  no disagreement against the independent expected records;
- passing current/base oracle comparisons, with finding comparison explicitly
  recorded as a separate real-Grype gate.

| Maximum across the 24 resource receipts per architecture | AMD64 | ARM64 | Frozen ceiling |
| --- | ---: | ---: | ---: |
| CPU time | 37.951362 s | 41.335111 s | 120 s |
| Wall time | 38.073317 s | 41.456446 s | 150 s |
| Charged peak memory | 619,118,592 bytes | 618,610,688 bytes | 2,147,483,648 bytes |
| Peak PIDs | 11 | 11 | 256 |
| Swap / OOM kills | 0 / 0 | 0 / 0 | 0 / 0 |

These are maxima across different finite workloads, not a single combined
workload or a throughput/capacity measurement. The 100k/100001 arms exercise
documented refusal behavior; they do not prove complete export of arbitrary
100k-occurrence graphs. The complete flat-pin envelope remains 10k.

The compressed-growth receipts report 205,856,758 bytes AMD64 and 201,119,441
bytes ARM64 under the 262,144,000-byte ceiling. Their baseline is the PR base,
**not the frozen S01 baseline**, so they do not establish cumulative milestone
growth. The images are CI-built image IDs rather than published registry digests.

The [frozen S01 baseline receipt](M046/S07/frozen-s01-baselines.json) now records
the verified retained OCI archives from run 37590730428 and their 13-layer
pre-inventory prefixes. `verify-inventory-release-size.py --frozen-s01` requires
those exact archive hashes and the anchored independent review. It excludes
S01's extra feasibility layer from the baseline, keeping that layer charged as
M046 growth. Substituting a newer PR base fails rather than reporting zero growth.
This prepares the cumulative gate; a qualifying release still must run it.
The recovered prefix also equals all 13 compressed descriptors in the
[S01 image pins](M046/S07/frozen-s01-image-pins.json), retained byte-for-byte from
source `d98fbd0fb9c5563999a5c061a12fb68191fddd86`. The gate checks both evidence
anchors and records the actual v1.7.38 native baseline manifest, separately from
the feasibility image's manifest.

```sh
python3 scripts/verify-inventory-release-size.py --frozen-s01 \
  --architecture amd64 --baseline /retained/s01-amd64.oci.tar \
  --candidate /published/release-amd64.oci.tar \
  --candidate-image /observed/native-image-inspect-object.json \
  --output /receipts/cumulative-growth-amd64.json
```

The candidate inspection file is the native Docker image object, not its enclosing
array. Its config digest must match the verified candidate OCI config. Repeat for
ARM64 and retain both native receipts with the release's registry manifest identities.

Both real-Grype receipts use the same advertised advisory build time and upstream
archive generation. Their locally prepared snapshot and database byte digests
differ. Preserve these separate identities; do not claim byte-identical frozen
advisory snapshots across architectures from this run. Release acceptance must
record the exact frozen inputs consumed on each architecture and establish the
reviewed equivalence rather than inferring it from the build timestamp.

Reproduce the audit with `scripts/audit-m046-native-ci.py`. Supply a directory
containing GitHub API `run.json`, `artifacts.json` and these eight downloaded zip
files: `inventory-{maintenance,entrypoint,real-grype,source-expectations}-{amd64,arm64}.zip`.
The script verifies recorded archive digests before reading any receipt, never
extracts/executes archive contents and always emits `acceptance: false`.

```sh
python3 scripts/audit-m046-native-ci.py \
  --artifacts-directory /path/to/downloaded-run \
  --output /path/to/native-ci-audit.json
```

## Required release identity and native demonstration

The latest published release inspected is
[v1.7.38](https://github.com/sourcebastion/sourcebastion-scanner/releases/tag/v1.7.38),
source `d64123b32be61b634a8b20d390c0cb6efaeefe91`, published 2026-10-05.
It predates the qualifying M046 integration. Its existence is not S07 evidence.

After normal release review, bind one qualifying tuple to immutable receipts:
scanner source SHA and release tag; OCI index and AMD64/ARM64 manifest/config
digests; installed inventory entrypoint/module and native tool hashes; reviewed
Python/APK/wheel locks and runtime pins; discovery/config, registry/parser/schema
versions and digests; source-authored corpus and designated source commit hashes;
advisory archive, imported database, schema and verified snapshot identities;
platform source/image digest, migrations and validator identity. Retain the prior
admitted tuple for rollback. A moving `latest` tag cannot identify either tuple.

| Required check | Execution and retained evidence | State |
| --- | --- | --- |
| Published native binaries | Pull the reviewed digest on actual native Linux AMD64 and ARM64. Validate installed payloads and run the independent corpus using those payloads, without replacing them with checkout modules. Record architecture/kernel, image/native hashes, expected/observed records and canonical per-case digests. | Not run |
| Frozen advisory matching | Admit reviewed frozen inputs before the workload, disable scan-time refresh/network, and run actual Grype on the canonical SBOM. Record all four pip advisory groups per selected occurrence, matching identity, distinct incomplete-inventory/matcher-failure states and standards validation. | Not run on published digest |
| No mutation/execution/install/forge calls | Read-only source and filesystem policies, denied network, actual source pre/post hashes and execution observations covering adversarial fixtures. Record allowed tool invocations and child lifecycle; read-only/network settings alone do not prove every no-execution requirement. | Release observations missing |
| Bounds, cancellation and child cleanup | Three fresh-cgroup repeats per architecture of corpus, stress and actual installed entrypoint; inherited outer deadline, finite child/resource observers. Exercise timeout, cancellation and controller loss; prove owned descendants/containers reaped, no late publication and explicit refused/partial states. | Historical normal-exit evidence only |
| Cumulative image growth | Compare verified compressed OCI descriptors against the reviewed frozen S01 baseline, bound to each published native manifest. Record baseline identity and byte totals. | Missing |
| Numerical exceptions | Compare actual aggregate work with [frozen budgets](../evaluation/m046/release-budgets-v1.json); link any explicit reviewed exception. Do not increase ceilings silently or treat a refused arm as a complete result. | No new exception proposed |

The existing `release.yml` validates locally built images before publication,
then smoke-tests a staged digest. That flow is useful, but the staged hosted smoke
does not retain the complete independent corpus/resource/rollback acceptance
bundle for the published digest. S07 must add or run that proof explicitly.

Native CI now exercises the installed image's
`/usr/local/share/sourcebastion/inventory-go.json` for corpus/resource arms.
`verify-inventory-expectations.py` accepts this build manifest as its own schema
and binds its compiler/archive/source/native ELF digest/size and pre/post file
identities. Separately prepared provider evidence remains a supported CI input;
an image build manifest is not relabelled as provider preparation. Published
proof must use the installed path, without rebuilding the helper.

## Development acceptance on designated work

The development target and test account/repositories must be designated before
fresh work is submitted. Use the existing **8 CPU / 12 GiB** allocation; record
actual worker limits and the dependency job's narrower frozen budgets separately.
No customer scan replay, credit reset, production rollout, new allocation or
provider-credential change is part of this acceptance.

For each designated immutable repository commit, record the expected package
occurrences, versions, roots/environments, edges and per-input/ecosystem coverage
before scanning. Include custom pip inputs, a mixed Python/Node/Go/Rust repository,
empty/unsupported/ignored inputs and deliberately incomplete inputs. Use a fresh
scan through the development worker, accepted result handoff, finalizer, persisted
rows and customer-facing pages. Record job/generation/run/snapshot identity,
published scanner digest, frozen advisories and actual resource observations.

Acceptance must demonstrate all of the following through the real result path:

1. Expected inventory/edges and findings agree with the designated source oracle;
   unresolved or unsupported inputs remain visible and cannot display as clean.
2. Coverage distinguishes examined-and-no-findings, incomplete inventory and
   unavailable matching, including per-root/ecosystem cases and legacy unknowns.
3. An authorized user downloads a standards-valid SBOM whose bytes/digest agree
   with the accepted run. Another account and a revoked grant cannot download it.
4. Reuse preserves original immutable inventory/matching/artifact identity,
   quota and expiry; changed runtime/advisory/source facts refuse unsafe reuse.
5. Cancellation/controller loss, bounded failure and capacity/key refusal produce
   truthful results without partial publication or abandoned owned resources.
6. A human reviews the visible coverage/finding messages and SBOM download on
   development; retain the designated source/run identities and dated acceptance.

Disposable integration tests and screenshots alone do not establish this complete
development demonstration. Keep credentials and raw account data out of public
receipts; retain immutable hashes and sanitized expected/observed records.

## Rollback and mixed result compatibility

Record before/after development configuration and immutable tuples. Disable new
inventory activation or restore the previously admitted scanner/config/validator
tuple using the [maintenance runbook](M046-maintenance-runbook.md). Submit fresh
designated work on the prior tuple, verify ingestion and truthful legacy/unknown
coverage, then restore the reviewed candidate and submit fresh work again.

During both transitions, verify existing candidate and prior artifacts remain
unchanged and accessible under the same authorization/retention rules. Exercise
old scanner/new platform, new scanner/new platform and the supported rollback
consumer boundary with additive/unknown/malformed fields, missing inventory,
incomplete enumeration and unavailable matching. Unsupported combinations must
refuse clearly rather than silently dropping results. Do not overwrite prior
artifacts, reinterpret historical findings against today's advisories or relabel
legacy coverage as complete. Retain the tested compatibility matrix and exact
configuration changes with each run receipt.

## Closure gate

S07 can be accepted only after every row above is backed by inspected immutable
evidence, all seven slice criteria have accepted evidence, and the
[support matrix](M046-support-matrix.md), maintenance instructions, measured
capacity and rollback procedure match the qualified implementation. Link the
release, both native receipts, designated development/human acceptance and mixed
version/rollback receipts here and in #94/#88. Production rollout remains a
separate approval; M044 recovery and M045 measurement/usage acceptance remain open
under their own scopes.
