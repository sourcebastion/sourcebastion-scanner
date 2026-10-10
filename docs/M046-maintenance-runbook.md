# M046 inventory maintenance and release runbook

Owner: scanner maintainers. S06 implementation lives in scanner issue #93.
The executable gates below do not accept S06 or M046 by themselves. S06 needs
reviewed exact-head native evidence, S02–S04 acceptance, and distribution closure;
S07 additionally needs published-digest development and rollback evidence.
Its requirement-by-requirement record is the
[S07 acceptance ledger](M046-S07-acceptance.md).

## Supported release and identities

There is one complete Linux AMD64/ARM64 image, built by `images/Dockerfile`.
Standard is its historical name. Slim, micro, thin and semgrep tags are retired;
their old digests are historical artifacts with legacy/unknown inventory
coverage. No new variant drops an adapter to save space. The public CLI remains
on its existing route; maintenance proofs do not activate the private inventory
entrypoint or negotiate platform transport.

The [support matrix](M046-support-matrix.md) is authoritative for supported
source subsets. Enumeration, selected-version fidelity and evidenced edges are
independent. Unsupported/dynamic/ambiguous sources remain located partial
coverage; no recognized input means unknown, not an empty clean repository.
Ruby/PHP preserve the accepted S03 conservative lock subsets. Legacy scanner
package/finding parity was waived by the owner on 2026-10-09.

| Input | Maintained identity / verification |
| --- | --- |
| Python interpreter and base | `PYTHON_VERSION`, `.github/inventory-runtime-pins.json`, Dockerfile's immutable multiarchitecture base digest; actual native interpreter checked |
| Python dependencies | `.github/python-locks/manifest.json`, four native/libc profiles per group; exact versions, hashes, wheel closure and publisher attestations in scanner-integrity CI |
| Node and npm | Native signed Alpine APKs, pinned versions and SHA256 in `inventory-runtime-pins.json`; build preparation hashes bytes, APK signatures stay enabled, installed versions checked offline |
| Parser code and registry | Exact installed path/hash map, registry `VERSION` and `REGISTRY_SHA256`; source bytes and custom configuration digest are separate |
| Vendored npm-semver and Yarn | Version/source/archive manifests and exact file hashes, retained ISC/BSD notices; no project `npm install` |
| Maintained Go helper and restricted provider | `cmd/inventory-provider/toolchain.json`, go.mod/go.sum, all seven helper source hashes; static Go source helper is installed in the image with preparation manifest and Go/x-mod/SourceBastion notices; restricted-provider comparison binary remains separately prepared/mounted |
| Grype | `.github/scanner-versions.json`, verified native archive hash, held executable identity and offline version/status/analysis; no per-scan refresh |
| Advisory data | Existing externally prepared, verified snapshot and all admitted file hashes, schema/build identity; generation is prepared separately and reused read-only |
| CycloneDX schema | Pinned official 1.6 schema closure in `evaluation/m046/cyclonedx-schemas/`; schema validation is separate from successful export/matching |

`verify-inventory-packaging.py` runs in the installed image, offline, and emits
the source, parser, registry, lock and runtime version closure. Its receipt does
not attest license clearance, container custody or measured resources. Those
remain separate release inputs. The Python base digest and native manifest
digests came from the official Docker registry; Node/npm hashes came from the
native Alpine 3.23 package archives during trusted maintenance preparation.

## Upgrade review

Review upstream releases/security notices weekly and before each release.
This is a maintainer cadence, not a created recurring automation. Update pins
only in a reviewed PR; scanner-artifact/update and release preparation stay
outside customer scanning. A Python update must update the immutable Docker
base and both native manifest digests together with the interpreter and wheel
locks. `scripts/python_version.py update` resolves the official multiarchitecture
index and verifies both native manifests, config digests, architectures and
interpreter versions before changing the wheel locks or pins. Release preparation
stages `base-image-pins.json`, `inventory-runtime-pins.json`, `PYTHON_VERSION` and
the Dockerfile together. Registry or verification failures preserve the reviewed
files. Updating a tag or build argument alone fails installed verification.

Keep `tests/fixtures/inventory/corpus.json` and fixture bytes independent of tool
output. The hand-authored full-record oracle is
`evaluation/m046/canonical-source-expectations-v1.json`. Record why a source
supports each expected package/version/edge/disposition. Third-party output may
help comparison but cannot generate or replace the oracle.

Native expectation proofs now retain every observed contextual record. Compare
the candidate with both the current source-authored oracle and the immutable
PR/merge-group base oracle:

```sh
rtk proxy python3 scripts/verify-inventory-upgrade.py \
  --baseline inventory-base-oracle.json \
  --candidate inventory-source-expectations-native.json \
  --output inventory-upgrade-diff.json
```

The gate emits package, version/hash/range, edge, context and coverage diffs and
exits nonzero for any difference or missing/added case. Generated record IDs do
not define parity: records bind by source context, with ambiguity refused.
Counters retain multiplicity. Editing the candidate oracle cannot hide a
required custom-input disappearance because the base oracle is compared too.
Malformed, duplicate, oversized or incomplete evidence fails closed. Failure
output is retained for review. There is no automatic baseline refresh or
`--accept-all` switch. A deliberate semantic/oracle change requires a separately
reviewed scope decision and gate adjustment before adopting it; do not weaken
the base comparison in an ordinary dependency bump.

For finding changes, use complete actual Grype JSON from two executions under
the *same* admitted snapshot, rather than match counts:

```sh
rtk proxy python3 scripts/verify-inventory-upgrade.py \
  --baseline inventory-base-oracle.json --candidate inventory-source-expectations-native.json \
  --baseline-findings baseline-grype.json --candidate-findings candidate-grype.json \
  --baseline-snapshot "$BASELINE_SNAPSHOT_SHA256" --candidate-snapshot "$CANDIDATE_SNAPSHOT_SHA256" \
  --output inventory-upgrade-with-findings.json
```

Complete match rows, severity, locations, matching details and multiplicity are
compared. Missing matching output is refused, not interpreted as no findings.
Native PR CI builds the immutable base image and runs its own installed proof
alongside the candidate using the same source fixture and advisory generation;
the combined upgrade diff retains the two complete report hashes.
Changing the advisory snapshot is a separately recorded advisory update, so
the finding-parity gate refuses mismatched hashes. A corpus-only diff explicitly
reports findings `not-compared`; it cannot replace the native real-Grype proof.
That proof still checks the custom pip input and four expected advisory alias
groups under recorded data. Inventory/export/matching statuses remain separate.

## Add a format or a custom input

Registry formats are built-in dispatch identifiers, never import names or
commands. Add standard names/content detection in `inventory/registry.py`, a
bounded static parser, canonical adapter and source-authored positive/negative/
adversarial fixtures. Version the affected parser; revise registry VERSION for
a dispatch-policy change and verify the content digest changes. Expand the
support matrix before advertising support. Contract/schema versions change
only for a reviewed wire-contract change; parser/registry versions are separate.

An explicit custom mapping uses a root-relative normalized POSIX path and a
known format identifier in `DiscoveryConfig(mappings=((path, format),))`.
`relative_path` and `DiscoveryConfig` reject external/parent/symlink escapes,
duplicate mappings, unknown formats and limits above hosted ceilings. Includes
and constraints retain provenance and obey the same source/deadline ledger.
Ignore paths produce coverage evidence. Static `setup.py` reading never executes
the project. Customer mappings cannot enable a network, subprocess command,
dependency installation, new source root or additional timeout allowance.

To diagnose an unsupported input, examine the located input disposition,
format/parser version, coverage dimension, fixed reason code and retained
source digest. Keep unknown activation/ownership and unresolved declarations
visible. Do not log credential-bearing raw URLs/options or treat a missing
selected version as the range's minimum. Reproduce from immutable source bytes,
source/config/environment/engine/registry/tool/advisory identities and the same
limits; use a native network-denied image by digest. Equal source names or purls
are insufficient identity. Save complete canonical and matching bytes, not
only a screenshot or counts.

## Numerical release gates

`evaluation/m046/release-budgets-v1.json` mirrors S01's frozen ceilings.
`inventory_release.py` rejects silent ceiling changes. The host driver creates
a fresh dedicated Docker cgroup for each workload and verifies `cpu.max`,
`memory.max`, `memory.swap.max` and `pids.max` before continuing a stopped trusted
shell. It reads host `cpu.stat`, `memory.peak`, PID peak and OOM counters, checks
aggregate CPU use throughout, and retains the cgroup until final observations.
It removes its exact owned container on success, refusal, timeout or signal.
Missing counters/local daemon/native architecture fail the gate. Docker Desktop
and remote Docker clients cannot provide local host cgroup acceptance.

Every workload stays within 2 CPUs, 2 GiB charged memory, no swap, PID256,
120 aggregate CPU seconds and the one 150-second wall interval. The complete
private dependency-entrypoint job uses the original controller deadline for
runtime/advisory admission, composition, export, real Grype, recovery and final
validation. Lower outer deadlines still win; later stages gain no fresh ledger.
CPU polling can overshoot by one scheduling/poll interval; any final overage
fails acceptance. Kernel quota and the aggregate CPU watchdog are different
controls. This finite CI driver is not a production supervisor or administrator
fence. SIGKILL/controller-machine loss still needs the production parent lease
and lifecycle boundary before public activation.

On each native architecture, run three fresh-cgroup repeats of 1k, 10k, 100k
and 100001 flat pins, a 40-node/1560-edge npm graph and a 12-level diamond
requirements include expansion. Independent generators assert counts, versions
and edge evidence, and source hashes stay unchanged. Required complete direct
composition/export capacity is 10k flat pins plus the graph/expansion arms.
Larger arms may explicitly refuse frozen bounds with retained partial or failed
inventory coverage and a budget reason;
they cannot time out/OOM and report success. A 100k occurrence maximum is not a
promise to export/match every arbitrary graph. The complete native real-Grype
job supplies the aggregate-stage arm separately.

```sh
rtk proxy python3 scripts/run-inventory-resource-proof.py \
  --image sourcebastion:standard-rule-test --checkout "$PWD" \
  --workload stress --arm flat-10000 --output inventory-resources-flat-10000-1
```

Compressed growth uses OCI archives from exact baseline/candidate source
commits. `verify-inventory-release-size.py` verifies referenced manifest/config/
layer hashes and descriptor sizes without extracting archive paths. It charges
every new compressed blob against the 250 MiB per-architecture ceiling,
including changed base blobs; uncompressed Docker Size cannot satisfy this gate.
PR CI compares its immutable base. For final M046 release acceptance, also
compare with the frozen S01 baseline source/release, not only the previous PR;
successive small changes must not evade cumulative growth accounting.

## Reading a held container's output

The host driver holds each workload at a second `SIGSTOP` so every cgroup
counter is read after the work finishes and before the container is torn down.
A container held that way **has not committed its stream**, and `docker logs`
returns nothing for small output. Measured against the pinned base image with
the driver's own create/start/CONT/gate sequence:

| bytes the workload wrote | bytes `docker logs` returned while held |
| --- | --- |
| 20 | 0 |
| 4096 | 0 |
| 65536 | 65536 |
| 262144 | 262144 |

The threshold sits between 4 KiB and 64 KiB. Below it the bytes are invisible
until the container exits.

This is worth knowing because of how it presents. The stress and corpus
workloads emit large reports and were captured; only the dependency job's
receipt -- a few hundred bytes -- fell under the threshold. So the defect
looked specific to one workload, and the first hypothesis was a flush race.
That hypothesis was wrong, and it was wrong in a plausible direction: a race
would have affected the short stress arms most, not spared all eight of them.

The driver therefore releases the held shell and awaits the container's exit
before reading the stream, after its final observation. The exit file appears
before `printf` completes and before the second stop, so file existence is not
the handoff: the driver waits for the shell's stopped state before reading the
exit status, taking final counters or releasing it. Two rules follow for
anyone changing this path:

- never read a workload's output while its container is still held, whatever
  the output is expected to be;
- a proof must refuse an empty capture rather than record one. The receipt
  previously reported `status: passed` with `workload_sha256` set to the
  digest of the empty string, and the first thing to object was an assertion
  three layers downstream.

The container's exit status is also checked against the gate file the workload
wrote, because the wrapper exits with the workload's status; a disagreement
means the lifecycle is not what the receipt describes.

## Distribution closure and rollback

Preserve vendored parser notices and all shipped upstream license texts.
Record exact wheel/APK/tool digests, publisher/source provenance and a reviewed
notice/source-obligation closure per native image. S01 specifically left the
musl rpds bundled `libgcc_s.so.1` origin/notices/source obligation open; an APK
or wheel hash and an SPDX label do not resolve it. Inspect the actual current
wheel versions and `.libs` contents, identify each bundled native library's
publisher/source, and bind any clearance to those bytes. Moving optional
SPDX/licensing product work to M048 does not waive distribution obligations.

**Deferred to M049, by decision.** This section originally held that S06
release acceptance remains blocked without closure. That condition was
self-imposed here rather than required by
[S06 #93](https://github.com/sourcebastion/sourcebastion-scanner/issues/93),
whose acceptance sentence names native release jobs, upgrade gates, numeric
budgets, this runbook, exact-head CI and release evidence -- not closure. The
condition is therefore amended: closure is tracked as
[M049 #164](https://github.com/sourcebastion/sourcebastion-scanner/issues/164)
and does not gate S06.

This is a deferral, not a resolution. The obligation is live now, because the
image is published for `docker pull` today. The investigation is complete and
recorded in
[the closure evidence](M046-S06-distribution-closure.md): 19 vendored native
libraries across four packages, bound to digests, with provenance established
as Alpine 3.23 `aports`. What remains is notices, a source mirror and drift
detection -- mechanical work with no legal opinion sought, which is why it can
be sequenced after S06 rather than inside it.

Anyone reading S06 as accepted should not read it as compliant. Those are
separate claims and this paragraph exists to keep them separate.

Before S06 acceptance, retain exact source head, native image/manifest digests,
pin/module maps, all 64 corpus comparisons, full finding evidence, three-repeat
resource arms and frozen-baseline compressed-growth receipts. Distribution
closure is deferred to M049 as recorded above, so it is not part of this
retention set. All required current-head CI must pass. An unmerged
implementation or a local unit test run is not accepted release evidence.

For rollback, restore the previously admitted immutable image/config/parser/
registry/advisory tuple, invalidate inventories, compatibility keys and M036
incremental baselines made under changed identities, and preserve previously
stored artifacts and evidence. Label results without negotiated coverage as
legacy/unknown. Verify the prior tuple on designated development repositories,
including custom Python inputs and partial/unsupported cases, and confirm
authorized SBOM retrieval/isolation. Record expected/actual inventories,
findings, user-visible coverage and rollback digests in S07. Production rollout
and new infrastructure allocation remain separately authorized release work.
