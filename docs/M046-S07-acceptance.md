# M046 S07 acceptance ledger

Status: **accepted on 2026-10-11**. Published native qualification,
automated live development and rollback proofs pass. The designated reviewer
accepted the visible K/J3/H coverage and K findings/source review after platform
[#420](https://github.com/sourcebastion/sourcebastion-platform/pull/420) deployed.
Foreign-account refusal, fresh post-fix revoked-grant refusal and restored access
to the original K SBOM with its matching downloaded checksum pass. Original
failed attempts and frozen expectations remain preserved.
Tracking: [S07 #94](https://github.com/sourcebastion/sourcebastion-scanner/issues/94);
scope: [M046 #88](https://github.com/sourcebastion/sourcebastion-scanner/issues/88).

## Slice prerequisites

| Slice | Required evidence | Current state |
| --- | --- | --- |
| S01 | Independent corpus, engine decision and frozen numerical ceilings, with reviewed immutable receipts | Accepted by #88; [architecture decision](../evaluation/m046/architecture-decision.md), [independent review](../evaluation/m046/evidence/S01-independent-review.md). Final release must retain this baseline rather than comparing only against its immediately preceding commit. |
| S02 | Content validation, custom paths, exclusions and located discovery outcomes over the independent corpus | Accepted by #88 and [#90](https://github.com/sourcebastion/sourcebastion-scanner/issues/90). Revalidate against the published release. |
| S03 | Selected-version, declaration, occurrence and graph semantics on supported ecosystems; explicit unsupported outcomes | Accepted by #88 and [#91](https://github.com/sourcebastion/sourcebastion-scanner/issues/91). The owner waived legacy scanner parity, not truthful semantics or the minimum corpus. |
| S04 | Standards-valid CycloneDX, actual offline Grype, four pip advisory groups, matching identity and independent failure states | [Acceptance ledger](M046-S04-acceptance.md) records all five stated criteria met; #92 is closed. Published qualification below independently binds standards-valid export, real matching, the four original pip advisory groups and source equivalence to the release tuple. SPDX remains in M048 #154; live development and resource acceptance remain S07 requirements. |
| S05 | Immutable queryable rows, authorized artifact access, truthful root/ecosystem coverage, retention/reuse and development presentation | Foundation #403 and [platform #404](https://github.com/sourcebastion/sourcebastion-platform/pull/404) merged; platform merge `377f61d2c6e544b409b471250c20edcb40fa30f8`, reviewed head `402fd5b93058f3c1e291def04a520313731e65de`. [Scanner #162](https://github.com/sourcebastion/sourcebastion-scanner/pull/162) and [#165](https://github.com/sourcebastion/sourcebastion-scanner/pull/165) merged as `4effe1897114ef3e3c6cf17b52172d8ea3844986` and `899f1255320241b9e9ef7f7cc77152da6374083c`; both are included in the published release. Accepted: development runtime/validator binding, persistence, reuse, capacity/key refusal and rollback proofs pass. Platform #419 fixes the retained live revocation failure; fresh signed-in foreign/revoked download refusals and restored original bytes pass. Platform #420 supplies the deployed tabs; the designated reviewer accepted coverage and findings on 2026-10-11. See the final decision and human receipt below. |
| S06 | Verified native packaging, upgrade gates, numerical budgets, support/runbook, #54 coordination and release evidence | Implementation and release evidence accepted in the [S06 ledger](M046-S06-acceptance.md); S07 independently audited published native qualification and frozen-S01 growth below. [#163](https://github.com/sourcebastion/sourcebastion-scanner/pull/163) merged the distribution deferral to M049 #164; the obligation remains open there. |
| S07 | All preceding slices accepted, published native proof, development human acceptance and rollback/mixed-version receipts | Accepted on 2026-10-11; all required demonstrations and designated human sign-off are recorded below. |

Issue closure alone is insufficient. Each accepted slice must link its actual
criterion-by-criterion evidence and bind that evidence to the qualifying release
tuple. A later parser/config change requires review and the affected proofs again.

## Current release and qualification work

The v1.8.0 [release run 38095674451](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/38095674451)
failed after both staged hosted scans passed their scanner assertions: cleanup
could not remove deliberately sealed control directories. It did not publish;
the v1.8.0 release remains a draft. [#169](https://github.com/sourcebastion/sourcebastion-scanner/pull/169)
fixes private scratch cleanup, with exit-status and external-evidence regression
checks, and advances the version to v1.8.1. Both native jobs passed before merge.

The v1.8.1 [release run 38101710508](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/38101710508)
selects exact source `957e1670d1552c0e1056c3bdf1cd2c78108abfc6`. Both the reviewed
heads and merge commits of scanner #162 and #165 are ancestors of that source.
This replacement run received the required GitHub approval and completed
successfully. Independent public registry and signed release-workflow attestation
verification bound both version/source tags to index
`sha256:f007b57fb4ca3ad1ce432c5eabb4881ca84c64bbb4219a5b46379d36d61479a6`,
byte-identical to the tested staging index. AMD64 manifest/config:
`sha256:60851bee28a838a040c87dac1bb7b1d946250a198a73666684c67f2d67a2d3a2` /
`sha256:8c29d7386e23d46820797e369c2186d8bce066ce2fe735e24db0e99260608a7b`.
ARM64 manifest/config:
`sha256:c6ec51cb385755ae2ac173bed8679abc0db2a23ebafb1e052c8f7578ae270b69` /
`sha256:28f2a34e3e19fb545cd72eb1ebd764b263634a9e6bb868eb1844318b3a115e06`.
This establishes publication identity, not whole-S07 acceptance. The earlier
run 38089205320 was cancelled before publication because its source did not
contain both PRs.

The [earlier native CI audit](M046/S07/native-ci-audit-38094267046.json) verifies all
eight GitHub artifact digests from successful exact-head run
[38094267046](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/38094267046),
48 resource/workload bindings, six installed-entrypoint bindings and 64 equal
canonical case digests. Its AMD64 maxima are 32.895919 CPU seconds, 33.111418 wall
seconds, 618,926,080 bytes and 11 PIDs; ARM64 maxima are 41.950598 CPU seconds,
42.251301 wall seconds, 618,844,160 bytes and 11 PIDs. All are within frozen
ceilings. Its image-size receipts still compare against the PR base, and its two
advisory snapshot hashes differ. These are finite CI proofs rather than published
release acceptance.

The audit preserves the reviewed S05 corpus delta instead of concealing it:
baseline oracle `3fd21f9d1e0b4f9ae128a0dceb2a94a6043d780faa8c09e0ea85a320b1bb5ab2`,
candidate oracle `0fe1f2177e2d4743e17794befaf10099a68439924b7b9d41e3e54ce834cc601b`,
exact transition `cb6a613f4f17191352191ae49339afad36283df9298cf46d18c5d044af4aca18`.
It recomputes the difference against the archived immutable base oracle and
requires the exact committed approval. [M050](M050/ACCEPTANCE.md) now records
qualification of that existing approval path and its operational review process;
the historical S07 evidence is retained unchanged.

`.github/workflows/m046-published-proof.yml` prepares a finite published-image
qualification path. It requires an already published stable tag, its exact
source SHA and the published index digest. It checks the tag/index binding,
selects one actual native manifest per architecture, verifies pulled config and
retained compressed OCI bytes, and charges cumulative growth from the retained
S01 archives. Both native jobs consume the same separately prepared advisory
file set, verified before and after scanning. Installed module/runtime checks,
official CycloneDX validation, three corpus/stress cgroup repeats and three
installed-entrypoint repeats run against the published images. The comparison
job checks all 48 matrix/entrypoint workload bindings, repeat consistency, equal
canonical case digests and the shared release/advisory identities.

An additional corpus run and all three installed-entrypoint runs attach a host
process/network tracer before the trusted stopped shell releases the workload.
The trace follows descendant processes and retains execution arguments and
IPv4/IPv6 attempts, including failed attempts. Missing, truncated or premature
traces refuse qualification. Collection reports `trace-collected-review-required`;
the raw invocations still require review against the installed allowed tools.
This adds observations without claiming that isolation flags establish absence
of project execution or network attempts.

Published qualification passed in
[38104916825](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/38104916825)
at driver `843ab4c7fc80612044078e31f28f6cfe6baac530` against this exact tuple.
The [independent published audit](M046/S07/published-native-audit-38104916825.json)
checks all three native/comparison archive digests and the shared-input archive
against GitHub's SHA-256 records. It verifies all 48 resource/workload bindings,
64 equal canonical corpus cases, the complete shared advisory file set and its
3.22 GB database hash, and cumulative frozen-S01 growth of 206,007,354 bytes
AMD64 and 201,263,464 bytes ARM64. Complete 10k exports pass; 100k/100001 cases
retain their expected incomplete/refusal states.

The eight raw execution traces were independently reviewed: each corpus trace
contains 37 allowed executions (the installed Python proof, fixed installed
Node parsers and the hash-bound Go helper), and each installed-entrypoint trace
contains the installed isolated Python entrypoint plus exactly three hash-bound
Grype commands: version, database status and explicit SBOM matching. All observed
executions succeed; none of these traces records a network syscall or an IPv4/IPv6
attempt. Held descriptor paths are supported by the reviewed executable hash and
metadata guards and installed payload proofs, not treated as identity by themselves.
All six retained canonical inventories, exports and recovery maps were independently
replayed byte-for-byte; each preserves all ten required source/advisory groups,
including the original four pip groups independently on both custom source paths.

Across the 24 matrix/entrypoint receipts per architecture, maxima are 47.199806 CPU
seconds, 47.470222 wall seconds, 619,167,744 bytes and 11 PIDs on AMD64; 41.755441
CPU seconds, 42.078098 wall seconds, 618,856,448 bytes and 12 PIDs on ARM64. Every
receipt reports zero swap and OOM kills and removal of its owned container.
These are finite workload maxima, not throughput or a production capacity claim.
Complete independently verified public OCI archives are retained separately;
their native manifest, configuration and layer descriptors match this published
qualification. A different archive wrapper is not claimed to have the CI wrapper's
SHA-256.

The preceding qualification refused a completed corpus because ptrace reported
the shell's SIGSTOP group-stop as lowercase `t`. The corrected driver requires
that exact shell's recorded SIGSTOP group-stop; intermediate syscall stops cannot
qualify. All 122 affected checks pass. Failed receipts remain separate.
Qualification receipts retain `acceptance: false`; live development review,
adversarial lifecycle, mixed-version rollback and all-slice acceptance remain
separate. Passing this proof cannot close #94 by itself.

The existing Docker Validation workflow can invoke a reviewed driver branch
before the new workflow is registered on `main`:

```sh
gh workflow run docker.yml --ref <reviewed-driver-ref> \
  -f build_images=false -f published_release_tag=v1.8.1 \
  -f published_release_sha=957e1670d1552c0e1056c3bdf1cd2c78108abfc6 \
  -f published_image_digest=sha256:<verified-published-index-digest>
```

The development host's deployment marker was independently read on 2026-10-10:
`89f7e91b7a9dfb19804ccb35b512c4b19ea6fde0`. A merge is not a deployment.
The user corrected the designated repository to `ez-appsec/juice-shop` before
any acceptance scan was submitted. Read-only inspection using the platform's
normalized account key confirms one owned, authorized, enabled and entitled
project, with the account's active `ez-appsec` installation. Account contact
information and database identifiers remain private. The requesting user agreed
to review coverage, findings and the SBOM download in development, before any
fresh acceptance scan. This designation is not acceptance; the dated review
remains required after visible results exist. No activation, customer replay or credit
reset is established by these receipts.

The [corrected source-authored expectations](M046/S07/development-source-expectations-ez-appsec-juice-shop.json)
were written before scans from immutable commit
`0810fef353a6d0ed772890015e2d374715723328`. Their SHA-256 is
`db704b7540fd724ac9ea3a8f179bcb661a32c1dad3bbd797b4c42a48686e9aad`.
Two npm manifests declare 148 occurrences, including eight literal selected
versions. There are no standard lockfiles or evidenced package edges; unresolved
ranges and incomplete coverage must remain visible. The backup lock filename is
unconfigured. The earlier [first-target oracle](M046/S07/development-source-expectations-juice-shop.json)
is retained unchanged as a superseded designation, not evidence for this target.

Additional source-authored development fixtures are prepared locally on the
corrected repository at `d01f3278ca960530d1c9f1290324469531471124`, branch
`test/m046-s07-development`. Their [pre-scan expectations](M046/S07/development-fixture-expectations-ez-appsec-juice-shop.json)
hash to `df9dfad45661241ebf8cddba14851443126ffe17614e499c8f40d45084e3f049`.
Thirteen additional inputs cover custom pip and two separate pip 26.0.1
observations with four required advisory groups each, npm/Cargo lock edges,
unresolved Go/Python declarations, empty application manifests, ignored prose,
unsupported inputs and project-execution traps. Relative case expectations come
from the frozen source-authored corpus at `4effe1897`; final comparisons must
bind exact prefixed paths and contexts. The branch was subsequently pushed and [fixture PR #2](https://github.com/ez-appsec/juice-shop/pull/2)
submitted genuine provider work after actual runtime admission. Failed live
attempts and pending fresh acceptance evidence are recorded below; preparation
and normal retries do not establish fresh scan acceptance.

[Platform #405](https://github.com/sourcebastion/sourcebastion-platform/pull/405)
merged as `8b331bef13ace72672282a53c45c22bccba338f1`. It binds the companion
validator to exact v1.8.1 source `957e1670`, enables development read presentation
and provides the guarded exact-job production worker driver. The installed wheel
proof and 134 isolated development conformance/admission checks passed without
skips on Python 3.11. An additional three real-Docker tests passed against the
published AMD64 image: actual worker/handoff/finalizer and isolated SQL rows,
authorized/foreign-account route checks and two successive reuse passes with
unchanged row/artifact charges and expiry. These are isolated authored-fixture
proofs; live account presentation and authorization review remain separate.

A finite proof also exercised the actual installed entrypoint and production
Docker watchdog on the development host under deadline, cancellation and host
controller SIGKILL. All three refused, removed their exact owned containers,
reaped observed process birth identities, preserved source bytes and showed no
later artifact writes. Neither entrypoint nor watchdog was paused or replaced.
No live queue or accepted publication was involved.

Development deployment and actual application binding are now verified.
[Platform #408](https://github.com/sourcebastion/sourcebastion-platform/pull/408)
retains the required scanner proof on the established fast pool while application
deployment stays on the slow pool. Its scanner gate passed; deployment then
refused advisory refresh. [Platform #409](https://github.com/sourcebastion/sourcebastion-platform/pull/409)
validated reuse of a recent retained generation with independent pinned Grype
hash/age checks and deployed successfully in
[38108213701](https://github.com/sourcebastion/sourcebastion-platform/actions/runs/38108213701).
The daily updater remains unconditional and seven-day retention is unchanged.

The actual application Python 3.11 environment received exact validator wheel
`27b1e71f2f42f509243112c57e84af7b5d4b9cc5e8e01642eb2182d93b6287b2`,
its pinned pure-Python dependencies and a healthy service restart. Installed
owned payloads, import origins, runtime manifest and stable artifact keys passed
verification. Persistent inventory writer, reuse and queue-adoption flags remain
disabled; read presentation is enabled. The existing allocation was independently
verified from Proxmox as eight CPUs and 12 GiB RAM; dependency containers retain
two CPUs, 2 GiB RAM, zero swap and 256 PIDs. No new allocation was made.

The first genuine designated job refused before publication because inventory
selection reacquired its job-row lock after commit, blocking independent lease
polling. [Platform #410](https://github.com/sourcebastion/sourcebastion-platform/pull/410)
releases that transaction boundary. A real PostgreSQL red/green regression and
mandatory CI pass; actual deployment
[38109834411](https://github.com/sourcebastion/sourcebastion-platform/actions/runs/38109834411)
passed at `db3e67c8beb565c2235724307065f8320ac86317`.

The existing job's normal retry passed that boundary, then exhausted the
dependency allowance hashing advisories with a PostgreSQL lease query every
64 KiB. It was cooperatively drained without publication or remaining admitted
compute. [Platform #411](https://github.com/sourcebastion/sourcebastion-platform/pull/411)
keeps complete byte hashing and bounded reads, polls leases at file boundaries
and every 250 ms of streaming progress, and enforces the unchanged dependency
deadline on every read. All CI passed and it merged as
`858862b654b268d8b97aa0bf74f8340a71914d82`. Its exact candidate hashed the full
3,222,298,624-byte frozen database to the same SHA-256 in 17.53 seconds with 77
read-only database checks. That callback proof is not an executing scan lease.
Actual deployment passed in
[38111127532](https://github.com/sourcebastion/sourcebastion-platform/actions/runs/38111127532),
and the installed validator, keyring and disabled persistent writer/reuse/adoption
defaults were verified again against the healthy deployed revision.

The third owned compute attempt completed dependency scanning, then spent minutes
projecting inventory because its 128,419 cancellation callbacks each queried
PostgreSQL. The same unpublished canonical bytes projected locally in 0.70 seconds.
The attempt was cooperatively drained; the original job exhausted its three
compute attempts and was finalized as terminal failed through the normal provider
path. No inventory or accepted result was published by that job.
[Platform #412](https://github.com/sourcebastion/sourcebastion-platform/pull/412)
bounds inventory cancellation polling to 250 ms while preserving immediate
known-loss, expiry, drain and phase/generation checks and every durable effect
fence. Its 138 focused tests and all CI, including the PostgreSQL contract, passed.
It merged as `50c366049c48e4f96c02377c6e5bf61c369901b2` and deployed successfully in
[38112428605 attempt 2](https://github.com/sourcebastion/sourcebastion-platform/actions/runs/38112428605).
The first attempt refused an advisory refresh at the required scanner gate;
that failure is retained separately. Post-deployment validator/keyring/defaults,
healthy marker, empty queue and absence of active containers were verified.

Fresh provider commit `e1d3ff87d05cd41e135b9db488ad66f6b1f4f8f1` completed and
published a result, but [its independent comparison](M046/S07/development-first-published-audit.json)
failed the pre-scan Go expectations. The hosted controller hard-coded
`go_sha256=None`, yielding a truthful `go-parser-runtime-unavailable` outcome
instead of the image helper's source declarations. The remaining seven contextual
cases, 148 base declarations, eight selected base versions, all 522 inventory rows,
20 recovered matching rows and eight required pip advisory/path combinations
passed diagnostic replay. The actual exported bytes passed the pinned offline
official CycloneDX schema. This result remains intact and is not acceptance.
[Platform #413](https://github.com/sourcebastion/sourcebastion-platform/pull/413)
wires the installed helper and authenticates its digest through finalization,
with changed reuse compatibility to refuse pre-fix snapshots. Its 100 focused
tests and all CI pass. The [exact-head native proof](M046/S07/hosted-go-helper-native-audit.json)
passed the actual Docker worker with a Go module, then two successive reuse passes
with unchanged origin rows, artifact charges and expiry (338.47 seconds). These
remain isolated authored SQL fixtures rather than live account acceptance.
It merged as `58fdd2cf963db081f0e32f687570345446715787` and deployed successfully
in [38114332666](https://github.com/sourcebastion/sourcebastion-platform/actions/runs/38114332666).
Fresh commit `4e7289a38feb4305f82370a54515e3ddf1f11242` completed and
[passed the frozen content audit](M046/S07/development-go-fixed-content-audit.json),
including all eight contextual cases, 530 inventory rows, 20 matching rows and
the official CycloneDX schema. Its execution bound a full plan, but the findings
envelope fell back and ScanRun planning fields remain absent; it cannot qualify
as a reuse baseline. Same-byte diagnostic commit
`08bd160437f19787a9b32d4415edf40288fe0d0d` retained the complete other-scanner
report and reproduced `duplicate_finding`: KICS emitted eight repeated identities
that ordinary storage already reduces by its first-observation rule.
[Platform #414](https://github.com/sourcebastion/sourcebastion-platform/pull/414)
applies that same rule before constructing the hosted envelope. Its 98 focused
tests pass, and [the exact retained report replay](M046/S07/development-envelope-dedup-replay.json)
produces a valid 128-finding envelope with all persisted finding fields equal.
It merged as `d321f8885754051bb692c97eca2d76f8e9c15761` after CI passed and
deployed successfully in
[38117244954](https://github.com/sourcebastion/sourcebastion-platform/actions/runs/38117244954),
attempt 2. The first attempt failed pip bootstrap before the scanner image proof
ran; its failed log and digest-verified artifact remain retained separately.
Fresh commit `954c8f5ee8bb77dea2ac63dbe176a1c2575d9e5e` then completed with a
persisted qualifying full plan. The [full-scan and publication audit](M046/S07/development-full-and-reuse-publication-audit.json)
verifies all eight frozen contextual cases, 530 inventory rows, 20 matching
rows, the eight required pip source/advisory groups, and the official CycloneDX
schema. The original source expectations remain unchanged.

The first fresh reuse commit `c9de07d5eddc1b1482336c6f21e20a7594c74a77`
persisted incremental run 113 with origin run 112, identical canonical/export
bytes and unchanged row/artifact quotas. Publication failed: nine carried
findings had no title or description, so their annotations had empty messages.
GitHub returned the correlated failure check with zero annotations. Recomputing
the exact old nine-annotation body reproduces its recorded intent digest;
the returned content does not. Normal finalization exhausted its three attempts,
retained the accepted artifact and unconfirmed provider journal, released
admission, and settled the execution failed/unknown/unavailable. No uncertain
annotation append was replayed and no original attempt was reset.
[Platform #415](https://github.com/sourcebastion/sourcebastion-platform/pull/415)
uses retained finding names/rules for nonempty annotation messages and permits
the designated test preflight to retain a validated settled quarantine without
classifying it as active work. Its 172 focused tests and mandatory CI passed,
and it merged as `1f182f47ef5c94ac86c2c38ba9cfb0c5bf9f36ae`. Deployment
[38119437577](https://github.com/sourcebastion/sourcebastion-platform/actions/runs/38119437577)
passed the scanner gate but refused application release: PostgreSQL JSON
projection attempted to unescape unrelated finding content on the development
SQL_ASCII database. The healthy application remained at the previous revision;
the accepted result and quarantine were not rewritten.
[Platform #417](https://github.com/sourcebastion/sourcebastion-platform/pull/417)
reads bounded private JSON text and exports only the original result metadata.
Its [retained regression proof](M046/S07/development-release-reader-regression.json)
binds 85 focused tests, disposable PostgreSQL baseline failure/candidate success
and a read-only candidate inventory of the actual development queue
pass. All CI passed on the unchanged commit after unused runner cache cleanup,
and it merged as `9bb1f59cb6389bb0a2ab4b02f0638d4cc3f248d9`. Normal development
deployment [38121640429](https://github.com/sourcebastion/sourcebastion-platform/actions/runs/38121640429),
attempt 2, passed; attempt 1 refused an advisory refresh before changing development
and its digest-verified diagnostic artifact is retained separately. The actual
deployed validator, keyring, retained settled quarantine and disabled persistent
writer/reuse/adoption defaults passed verification with the worker paused/drained.
Fresh commits `7b9b9584611b055e5888449a769eba904f8b1790` and
`bcf221b651a80fd842b1704301a06587a15fc7f7` then completed and published normally,
on their first compute attempts. The [independent successive-reuse audit](M046/S07/development-live-reuse-audit.json)
verifies runs 114 and 115 both reuse origin run 112, skip Grype execution, create
zero direct inventory rows/snapshots/artifacts, and retain byte-identical original
records, snapshots, artifacts, expiry and account quota charges. Both pass the
frozen contextual content/matching audit and official CycloneDX schema. The
failed predecessor remains intact and is excluded from these two demonstrations.

Inspection of the actual SBOM read authorization found that an existing
provider repository grant was checked for presence but not its current
`authorized` state. [Platform #416](https://github.com/sourcebastion/sourcebastion-platform/pull/416)
adds that state check. Three route regressions revoke and restore the grant
through the real capacity API; the baseline incorrectly returns 200 after
revocation, while the candidate returns the uniform 404/no-store refusal and
restores access to the original bytes after reauthorization. Its 110 focused
tests and mandatory CI pass. It merged as
`02a8e6c3ed9bbf999fc55b2decea823e5da76ecf` and normal development deployment
[38122770228](https://github.com/sourcebastion/sourcebastion-platform/actions/runs/38122770228)
passed. The deployed validator, keyring, retained quarantine and disabled persistent
defaults were verified again with the hosted worker paused/drained. The designated
human's live second-account/revoked-grant checks remain pending.

Eight [prefixed canonical case expectations](M046/S07/development-prefixed-canonical-expectations.json)
were mechanically derived from the frozen rich source oracle before the new
fresh acceptance commit was pushed. They preserve complete contextual records
and per-input outcomes, binding generated IDs by unique source anchors. Shared
global coverage and stage status are assessed separately; neither original
oracle was changed to match scan output.

The [live invalidation audit](M046/S07/development-live-invalidation-audit.json)
verifies three successive fresh provider commits and full runs 116–118. Changing
only the predeclared runtime row limit, then the frozen advisory file identity,
then the source range bytes refuses reuse. Each run creates its own 550 records,
two snapshots and two artifacts with exact new row/byte/artifact charges, and
passes contextual content, matching and official schema checks. Runtime/advisory
changes alter the component key; source equality is a separate mandatory guard.
The auditor's initial contrary key assertion and failed output are retained;
its correction checks that separate source guard and fresh plan without changing
the frozen source expectations. Capacity, key, bounded matching and rollback
cases follow below.

The [live capacity/key/rollback audit](M046/S07/development-live-capacity-key-rollback-audit.json)
verifies the predeclared one-row account limit refuses storage with
`inventory_row_quota_exceeded`, zero direct inventory publication and unchanged
row/artifact charges. A fresh scan on the retained prior `707fc32a` image with
writer/reuse disabled completes; the actual deployed presentation reports
inventory unknown and matching unavailable. Restoring the qualifying candidate
first refuses missing artifact keys before claim, with the queued row unchanged,
zero attempts and no owned container or worker receipt. The same fresh job then
completes as a full scan with exact new charges, all contextual/matching checks
and official schema validation passing. Pure read-only captures after both
transitions preserve the rows, artifacts, expiry and exact bytes of three earlier
stored origins, including the qualifying full baseline. No keyring rotation,
quota reset or historical attempt replay was used. Original bounded-attempt
failures and the separate fresh recovery demonstration are recorded below.

The predeclared 6,000-line bounded case instead reached the unchanged aggregate
CPU ceiling. Its [terminal refusal audit](M046/S07/development-live-cpu-refusal-audit.json)
retains the supervisor's 120,044,568 microseconds, one failed compute attempt,
no accepted run and unchanged quotas and earlier artifacts. It is not counted
as inventory-present/matching-unavailable acceptance. Its original source oracle
remains unchanged. A separate [2,000-line source expectation](M046/S07/development-bounded-matching-2000-expectations.json)
is frozen before any corresponding source edit or submission, to reach the
consumer boundary within the same runtime limits. No existing attempt is reset
or replayed and no numerical ceiling is increased.

The 2,000-line case J2 also remains failed with its original expectation unmet.
Its [capture-refusal audit](M046/S07/development-live-J2-capture-refusal-audit.json)
records a terminal job without an accepted run. An isolated replay using the
same source and published image finished Grype, then refused recovery at the
unchanged provider node budget. The parent tried to materialize the resulting
37,197,996-byte diagnostic through its 16 MiB capture bound, discarding usable
canonical inventory/export. [Platform #418](https://github.com/sourcebastion/sourcebastion-platform/pull/418)
stream-verifies this diagnostic without making it matching input, preserving
all original integrity/resource guards. Its 89 focused checks and immutable
isolated artifact replay pass. All 27 checks passed for reviewed head
`ae0af4970ae44ea464425ba78e9612fa55cc8f56`; merge
`2e3c7dc93e3ff09d251fec6d09168c593e78af6d` normally deployed in successful run
[38127054354](https://github.com/sourcebastion/sourcebastion-platform/actions/runs/38127054354).
The actual application validator, keyring, queue and persistent defaults passed
post-deployment verification.

A separate [prospective recovery-refusal oracle](M046/S07/development-bounded-recovery-expectations.json)
defines fresh case J3 using the same authored 2,000-line source, before its new
commit or submission. It requires successful inventory/export, unavailable
matching, the real recovery node-budget refusal, and no accepted matcher input
or fresh Grype findings. Both original J/J2 oracles remain byte-for-byte unchanged;
their failures are not relabelled as passes.

The [fresh recovery/restoration audit](M046/S07/development-live-recovery-restoration-audit.json)
now passes through the real worker, accepted handoff and finalizer. J3 at source
`3269d964a9641cd95e76745c411729eb82f7bed6` finishes its first compute attempt with
4,533 exact inventory rows, one inventory snapshot, two stored artifacts and
zero matching rows or fresh Grype findings. Its 2,000 located declarations and
selected occurrences agree with the prospective oracle. The independently
retained 37,197,995-byte diagnostic reproduces the unchanged provider node-budget
refusal; the authenticated capsule contains no accepted matching input. Inventory
and the standards-valid 2,015-component SBOM remain available. Dependency CPU is
within the unchanged 120-second ceiling, and all owned containers are removed.

The final fresh K scan at source `d24770870ab6dda3eac4fe8bb33d5c9085229788`
restores exact earlier tree `8c5e1cd8bf31f9f17aa760eaee9ea77bd83d4b50` and passes
as a full scan: 530 inventory rows, 20 matching rows, two snapshots and two
artifacts. All original contextual cases, 148 base declarations, eight base
selected versions and all eight pip source/advisory groups pass. Its official
CycloneDX validation passes with 15 components, and canonical/export bytes equal
the preceding normal I restoration. Both J3 and K incur exactly their new row
and artifact charges. Existing rows, snapshots, artifact bytes and expiry for
three earlier origins remain unchanged through the final transition.

Read captures of the actual deployed presentation function distinguish K's
partial inventory/ready matching, J3's partial inventory/unavailable matching,
and the legacy H result's unknown inventory/unavailable matching. These captures
forbid SQL writes and roll back all transactions; they do not establish browser
or human acceptance. After verified quiescence, both temporarily disabled GitHub
workflows were restored to active, the application worker cron reinstalled and
the worker resumed. Persistent inventory writer/reuse/M044 adoption remain off;
inventory read presentation remains on. At restoration, all designated signed-in
download checks, the actual downloaded checksum and dated human review were pending.

At that preparation checkpoint, the requesting user was designated to perform
the live second-account and revoked-grant refusal checks and review coverage,
findings and the authorized download. Their subsequent observations and final
sign-off are recorded below.
Failed attempts and normal retries are retained separately and
cannot substitute for fresh designated acceptance work.

### Human download checks (2026-10-11)

The designated reviewer signed in with the designated second development account
and confirmed that the exact K snapshot download request returns **404**, with
the response **Not available**. The earlier reported 200 was clarified to belong
to `/account/sbom`, which rendered an empty workspace; it was not a download
response. The [sanitized human observation](M046/S07/development-human-download-review.json)
records the result separately from the automated proofs. This is a user-reported
browser observation, not an agent-authenticated request.

The designated owner subsequently downloaded K's SBOM and pasted the local
checksum output for `sbom.cdx.json`. Its actual SHA-256 is
`42363ae7885516f71bbcb7d578ab0d912d4084324e6d70b0229aa765c32e22de`,
which equals the frozen expected digest of the accepted K artifact. This actual
download observation is separate from the earlier source-side integrity proofs.

The foreign-account refusal and owner-download integrity criteria passed at
this checkpoint. Acceptance still required the owner to review K/J3/H coverage
and K findings, confirm 404 after revoking only the test repository grant, and
restore access to the original download bytes. Those subsequent results and
final sign-off are recorded below. No account identifiers, session credentials or
private snapshot links are included in the public receipt.

The subsequent owner revoke test **failed**: the K SBOM remained downloadable
after the test repository was deselected from the development App installation.
Read-only inspection confirms that the provider's complete current repository
list excludes the test repository, but its platform grant remains authorized.
The durable webhook was marked applied with `repository_selection: selected`,
`action: added`, six additions and an empty removal list. Explicit-delta handling
did not revoke the omitted grant. [Platform #419](https://github.com/sourcebastion/sourcebastion-platform/pull/419)
adds current-membership reconciliation and failure refusal. Its 152 focused tests
pass, including a retained-artifact download regression that fails on the
baseline and a mixed-case canonical account regression that failed on the first
candidate. All 31 checks on reviewed head
`31cde1d26f619b1f7380a760ea150383116c239f` passed or were skipped as expected.
The fix merged as `af1c361b32ae15ee11645d72e4f282c9f557ab1e`; normal development
[deployment 38159496574](https://github.com/sourcebastion/sourcebastion-platform/actions/runs/38159496574)
passed on attempt 2, and installed verification confirms the exact reviewed fix
files, healthy service, configured artifact keyring and resumed normal worker.
Persistent writer/reuse/recovery remain off; read presentation remains on. The
initial rollout failed refreshing Grype advisories; its failure is retained.
Two verified byte-identical historical advisory database copies now share storage,
preserving every generation path, database byte and metadata receipt, to recover
6.4 GB before the same-source retry. At that deployment checkpoint, a fresh
designated revoke/restore test remained required. The original failed observation
is preserved independently;
neither the earlier foreign-account 404 nor the matching owner checksum proves
this revoked-grant criterion.

On 2026-10-11 the designated reviewer confirmed HTTP 404 on the exact K download
while the test repository was deselected after the deployed fix. Read-only
corroboration records the removal delivery applied at `2026-10-11 18:05:03+00:00`
and the bound repository grant unauthorized with reason `deselected`. This fresh
revoked-grant refusal passes independently of the preserved original failure.
An additional actual K checksum report also matches the frozen expected digest;
that report preceded this latest revocation and does not establish subsequent
restoration. The designated reviewer subsequently confirmed the K SBOM is present,
pasted fresh local `shasum -a 256 sbom.cdx.json` output equal to
`42363ae7885516f71bbcb7d578ab0d912d4084324e6d70b0229aa765c32e22de`,
and explicitly confirmed the checksum matches. Read-only corroboration records
the later repository addition applied at `2026-10-11 18:07:21+00:00` and the
bound grant authorized. Restored access to the original bytes after the fresh
404 passes. The remaining visible K/J3/H coverage and K findings review was
subsequently accepted by the designated reviewer, as recorded below.

### Deployed tabs and final human sign-off (2026-10-11)

[Platform #420](https://github.com/sourcebastion/sourcebastion-platform/pull/420)
renders stored occurrences and per-input outcomes in Dependencies, and accepted
matching rows with recorded fixes and exact package/source details in SCA.
All 31 pre-merge checks on reviewed head
`c23905c1ebc27c3cfbc5ae2e8120914c760c1e53` passed or were skipped as expected.
Merge `08d0b500fab703e64650658ec8906c2573191300` normally deployed in
[run 38172712480](https://github.com/sourcebastion/sourcebastion-platform/actions/runs/38172712480),
attempt 1. Read-only installed verification confirmed source hashes, service
health, keyring, restored test grant and resumed normal worker. Installed rendering
confirmed all eight K pip source/advisory associations, J3 unavailable matching
with inventory retained, and H unknown inventory with no export. Automated
rendering is recorded separately from human acceptance.

After this deployment and the exact review instructions, the designated requesting
reviewer explicitly reported **"signed off"**. This accepts the remaining visible
K/J3/H coverage and K findings/source review. The dated, source-bound
[human receipt](M046/S07/development-human-download-review.json) records this
sign-off separately from the already completed download/refusal observations.
No repeated download test, source change, quota reset or rescan was needed.

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

The qualifying published release inspected is
[v1.8.1](https://github.com/sourcebastion/sourcebastion-scanner/releases/tag/v1.8.1),
source `957e1670d1552c0e1056c3bdf1cd2c78108abfc6`, published 2026-10-11 UTC.
Its identity and finite native qualification are verified above; automated live
development, mixed-version rollback and designated human acceptance pass.
The prior admitted development image remains preserved for rollback.

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
| Published native binaries | Pull the reviewed digest on actual native Linux AMD64 and ARM64. Validate installed payloads and run the independent corpus using those payloads, without replacing them with checkout modules. Record architecture/kernel, image/native hashes, expected/observed records and canonical per-case digests. | Passed on both published native images; 64 equal cases |
| Frozen advisory matching | Admit reviewed frozen inputs before the workload, disable scan-time refresh/network, and run actual Grype on the canonical SBOM. Record all four pip advisory groups per selected occurrence, matching identity, distinct incomplete-inventory/matcher-failure states and standards validation. | Published and live matching/schema and required advisory groups passed; live unavailable-matching presentation verified and designated human review accepted on 2026-10-11 |
| No mutation/execution/install/forge calls | Read-only source and filesystem policies, denied network, actual source pre/post hashes and execution observations covering adversarial fixtures. Record allowed tool invocations and child lifecycle; read-only/network settings alone do not prove every no-execution requirement. | Eight published raw traces reviewed with allowed invocations and no observed network syscalls; source guards and installed pre/post payloads passed |
| Bounds, cancellation and child cleanup | Three fresh-cgroup repeats per architecture of corpus, stress and actual installed entrypoint; inherited outer deadline, finite child/resource observers. Exercise timeout, cancellation and controller loss; prove owned descendants/containers reaped, no late publication and explicit refused/partial states. | All 48 published normal-exit resource bindings passed; actual installed AMD64 deadline/cancellation/controller-loss proof passed in development isolation; live CPU, capacity and key refusals plus final restoration passed |
| Cumulative image growth | Compare verified compressed OCI descriptors against the reviewed frozen S01 baseline, bound to each published native manifest. Record baseline identity and byte totals. | Passed against frozen S01: 206,007,354 bytes AMD64; 201,263,464 bytes ARM64 |
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

## Final acceptance decision — 2026-10-11

All seven slices have accepted evidence. S04 and S06 retain their own linked
criterion ledgers; S05's remaining development coverage/download criteria and
S07's human gate are now accepted by the designated reviewer. The finite
release/development evidence satisfies the unchanged requirements above:

| Acceptance requirement | Retained evidence | Result |
| --- | --- | --- |
| Published native corpus, real matching/schema, execution observations and frozen resource/image budgets | [Published native audit](M046/S07/published-native-audit-38104916825.json) and verified v1.8.1 release tuple above | Passed on AMD64 and ARM64; no new budget exception |
| Source-authored inventory, contextual outcomes, pip advisories and immutable successive reuse/publication | [Full scan](M046/S07/development-full-and-reuse-publication-audit.json), [successive reuse](M046/S07/development-live-reuse-audit.json) | Passed with original expectations and origins unchanged |
| Runtime/advisory/source invalidation, capacity/key refusal and legacy rollback/restoration | [Invalidation](M046/S07/development-live-invalidation-audit.json), [capacity/key/rollback](M046/S07/development-live-capacity-key-rollback-audit.json) | Passed; refused work did not publish or charge inventory |
| Honest bounded matching failure and final source restoration | [J3/K audit](M046/S07/development-live-recovery-restoration-audit.json) | Passed; J3 preserves inventory/SBOM with unavailable matching, K restores full matching |
| Human-visible coverage/findings and actual authorized/foreign/revoked/restored download checks | [Designated human review](M046/S07/development-human-download-review.json) | Accepted; original K download SHA-256 matches the frozen expectation |
| Supported behavior, maintenance and rollback instructions | [Support matrix](M046-support-matrix.md), [maintenance runbook](M046-maintenance-runbook.md), [S06 ledger](M046-S06-acceptance.md) | Linked to the qualified implementation and release |

Original J CPU and J2 diagnostic-capture refusals remain failed with their
unchanged unmet expectations. J3 uses a separate prospective oracle and supplies
the required honest matching-unavailable demonstration; K supplies restoration.
The initial revoked-grant download failure remains recorded as failed; platform
#419 and a fresh designated 404 followed by restored matching bytes satisfy that
criterion. Historical automated receipts keep `acceptance: false` because they
were not human acceptance; this final decision and the human receipt supply it.

S07 and M046 are accepted for the stated development scope. Persistent inventory
writer/reuse/M044 adoption remain disabled, read presentation remains enabled,
and normal workers/workflows are resumed. Production rollout, M044/M045, M047's
full browser acceptance, M048 SPDX, M049 distribution and M050 process work retain
their separately recorded scope and decisions.
