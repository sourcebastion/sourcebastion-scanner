# M046 S06 acceptance ledger

Status: **every acceptance criterion S06 states is met**, with executable
evidence, and all of its implementation is on `main`. Exact-head CI, the
numeric budgets, coordination with
[#54](https://github.com/sourcebastion/sourcebastion-scanner/issues/54) and
**release evidence** are all satisfied. Distribution closure is **deferred to
[M049](https://github.com/sourcebastion/sourcebastion-scanner/issues/164)** by
decision, with the reason recorded below.

Release evidence was the last item, and it could only come from a real
release. It now exists: **v1.8.1**, published 2026-10-11 from `957e1670`,
validated and promoted in run
[38101710508](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/38101710508).
The detail is in [Release evidence](#release-evidence) below.

Tracking: [S06 #93](https://github.com/sourcebastion/sourcebastion-scanner/issues/93).
Canonical scope: [M046 #88](https://github.com/sourcebastion/sourcebastion-scanner/issues/88).

This file records what the slice establishes and what it does not, the same way
[S04's ledger](M046-S04-acceptance.md) does. It cites a release as evidence; it
is not itself a deployment, a product-route activation or an M046 closure.

## What S06 asks for, and where each part stands

| S06 requirement | State | Evidence |
| --- | --- | --- |
| Pin and verify inventory engine/runtime dependencies for native AMD64/ARM64 | implemented, in review | `.github/inventory-runtime-pins.json`; `scripts/verify-inventory-packaging.py`; pinned Python image digest and Node/npm APK versions with hashes |
| Enforce S01 image/resource budgets | implemented, in review | `evaluation/m046/release-budgets-v1.json`; `inventory_release.py` refuses silent ceiling changes; `verify-inventory-release-size.py` enforces the frozen 250 MiB added-layer ceiling from verified compressed OCI descriptors |
| Document image-variant behaviour rather than silently removing coverage | satisfied | One native image is shipped, decided in `5a38083` on 2026-10-03, before this slice. `DOCKER.md` and this runbook describe it; nothing was removed silently here |
| Keep source execution and scan-time network disabled by default | implemented | Every proof container runs `--network none --read-only --cap-drop ALL`; no project command is accepted by the host driver |
| Upgrade gates reporting package, version, edge, coverage and finding differences | implemented, in review | `inventory_upgrade.py`, `verify-inventory-upgrade.py`; compared against both the independent oracle and the immutable pull request base |
| Version the maintained format registry | satisfied | `registry.VERSION` with `REGISTRY_SHA256` bound over names, formats and rules, so a registry change moves the digest |
| Document adding a format, custom paths, unsupported inputs, reproducing from identity | implemented, in review | [`docs/M046-maintenance-runbook.md`](M046-maintenance-runbook.md) sections "Add a format or a custom input" and "Upgrade review" |
| Third-party scanner output is a comparison input, not the sole oracle | implemented, in review | `tests/test_inventory_maintenance.py::test_all_64_independent_cases_compare_and_generated_ids_do_not_define_parity` |
| Reuse the verified advisory snapshot; no per-scan refresh | implemented, in review | Base and candidate images are matched under one verified advisory generation; the snapshot mechanism is S04's, unchanged |
| Bounded concurrency and outer deadlines; no hidden timeout allowance | implemented, in review | The host driver takes the controller's original `deadline_monotonic` from `job.json` and lowers, never raises it; one shared wall interval across stages |
| Support, maintenance and rollback runbook published | implemented, in review | [`docs/M046-maintenance-runbook.md`](M046-maintenance-runbook.md) |
| Coordinate with [#54](https://github.com/sourcebastion/sourcebastion-scanner/issues/54) without assuming its older architecture | satisfied | Position stated and **agreement recorded** on [#54](https://github.com/sourcebastion/sourcebastion-scanner/issues/54). The `GrypeScanner.scan` caller and snapshot-refresh ownership stay open there, scoped out of this agreement |
| Numeric budgets pass on native hardware | satisfied | Exact-head run [38024740699](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/38024740699) on `3ac1928a`: every arm within the frozen ceilings, three entrypoint repeats at roughly 8.54 CPU seconds, 59 MiB peak and 11 PIDs |
| Exact-head CI | satisfied | The same run, green on AMD64 and ARM64, including the base-image mirror in every build path |
| Distribution closure | **deferred to [M049 #164](https://github.com/sourcebastion/sourcebastion-scanner/issues/164)** | Investigation complete: 19 vendored natives across four packages bound to digests in [the closure evidence](M046-S06-distribution-closure.md), provenance established as Alpine 3.23 `aports`. Not required by #93's acceptance sentence; the runbook's blocking condition was self-imposed and is amended. **A deferral, not a resolution** |
| Release evidence | satisfied | v1.8.1, run [38101710508](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/38101710508): the staged index `sha256:f007b57f...` passed `Test staged hosted scan` on **both** AMD64 and ARM64 and was promoted **unchanged** to `v1.8.1`, `957e1670...` and `latest`. See [Release evidence](#release-evidence) |

## The demo S06 specifies

> a candidate parser upgrade produces a reviewable graph/coverage diff and
> fails the gate when a required custom input disappears.

Both halves are exercised by
`tests/test_inventory_maintenance.py`: `test_full_semantic_dimensions_produce_reviewable_diffs`
for the diff, and `test_custom_input_disappearing_fails_even_if_the_oracle_is_edited`
for the refusal -- including when the oracle itself is edited to hide the loss,
which is the failure mode that makes a comparison oracle untrustworthy.

This is test evidence, not the demonstration on a release candidate that S06's
acceptance sentence asks for.

## Defects found and fixed while taking this over

The host resource proof reported `status: passed` for a workload that emitted
nothing, recording `workload_sha256` as the digest of the empty string. The
cgroup gate passed it on real measurements while the dependency job's receipt
was lost, and the first thing to object was an assertion three layers
downstream. The proof now refuses an empty capture before computing any digest.

The cause was not workload-specific. A container held at the driver's second
`SIGSTOP` has not committed its stream, and `docker logs` returns nothing below
a threshold measured between 4 KiB and 64 KiB. The large stress and corpus
reports came through; a few-hundred-byte receipt did not. The driver now
releases and awaits the container after its final observation, and checks the
container's exit status against the gate file the workload wrote. See the
runbook's "Reading a held container's output".

Two refusals were also hiding their own causes: the entrypoint proof's resource
gate and `owned_container` raised bare codes, and the driver reduced any
unexpected error to its class name. Both now carry bounded diagnostics, which
is what sent this investigation to the wrong layer twice.

## The capture defect, closed at exact head

The host resource proof reported `status: passed` for a workload that emitted
nothing. At exact head the entrypoint arm records `status: passed` with real
`workload_sha256` values across three repeats, where it previously recorded the
digest of the empty string. The receipt is captured, the budgets are measured
and the container is removed.

Two defects in the first fix were found in review and are also closed. Creating
the exit file precedes both the `printf` completing and the shell stopping, so
the driver now waits for the second stopped state before reading the exit code
or sending `CONT`; reading on file creation alone could see empty bytes, and an
early `CONT` is lost on a running process and strands the shell. Separately the
OCI candidate and baseline builds did not receive the selected base image
arguments, so they bypassed the mirror; the baseline now selects independently
from its own checkout's reviewed pins, because a baseline commit may pin a
different digest.

## Distribution closure is wider than S01 recorded

S01 left open "the musl rpds bundled `libgcc_s.so.1`" -- one library in one
package. The published image actually carries **19 vendored native libraries
across four packages** (`semgrep`, `rpds_py`, `pydantic_core`, `cryptography`),
including four distinct `libgcc_s.so.1` byte-sets, plus Alpine's own. Several
carry real copyleft source obligations rather than notice retention alone:
`libgmp` is LGPL-3.0-or-later, `libdw` and `libelf` are elfutils.

`rpds_py`'s own CycloneDX SBOM lists its 17 cargo crates and omits the bundled
`libgcc_s.so.1` entirely, which is the concrete reason a wheel hash plus an
SPDX label does not resolve this.

Evidence, bound to digests:
[`docs/M046-S06-distribution-closure.md`](M046-S06-distribution-closure.md)
and [`docs/M046/S06-bundled-natives-arm64.json`](M046/S06-bundled-natives-arm64.json).
Identification only; no clearance is claimed, and ARM64 alone was observed.

## Licensing compliance is deferred, not satisfied

Distribution closure for the bundled native libraries moves to
[M049 #164](https://github.com/sourcebastion/sourcebastion-scanner/issues/164).

The deferral is defensible on scope: S06's acceptance sentence in #93 names
native release jobs, upgrade gates, numeric budgets, the runbook, exact-head CI
and release evidence. It does not name distribution closure. The blocking
condition was written into the runbook by this slice, and is amended there with
the reason recorded.

It is not defensible as a claim of compliance, and this ledger does not make
one. The obligation is live today, because the image is published for
`docker pull` in `README.md` and `DOCKER.md`. Nineteen vendored native
libraries ship with no retained notices, and `libgmp` (LGPL-3.0-or-later) and
elfutils' `libdw`/`libelf` carry source obligations that notice retention alone
does not discharge.

What makes the deferral reasonable rather than convenient is that the hard part
is done. The libraries are enumerated and digest-bound, their versions match
Alpine 3.23 packages exactly, and Corresponding Source is Alpine's `aports`
with the build script and patches already assembled. M049's three slices are
mechanical, need no legal opinion, and modify no shipped binary.

**S06 accepted does not mean the distribution is compliant.** Those are
separate claims and should stay separate.

## Release evidence

S06's acceptance sentence names release evidence alongside exact-head CI.
`release.yml` does not run on a pull request, so no merge could produce it.
This is the run that did.

**v1.8.1**, published 2026-10-11T02:09:16Z from `957e1670`, run
[38101710508](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/38101710508).
It went through the designed initiator rather than the owner break-glass path:
`release-dispatch.yml` saw the `VERSION` change reach `main` and sent the bot
`repository_dispatch`, and `prepare-release` then held the run in the
`release` environment until a designated human approved it. The two attempts
before it were manual `workflow_dispatch` runs, which is why they needed a
version argument supplied by hand.

### The published image is the tested image

| Role | Digest |
| --- | --- |
| Staged index, built once and scanned | `sha256:f007b57fb4ca3ad1ce432c5eabb4881ca84c64bbb4219a5b46379d36d61479a6` |
| `v1.8.1`, `957e1670d1552c0e1056c3bdf1cd2c78108abfc6`, `latest` | the same `sha256:f007b57f...` |
| linux/amd64 manifest | `sha256:60851bee28a838a040c87dac1bb7b1d946250a198a73666684c67f2d67a2d3a2` |
| linux/arm64 manifest | `sha256:c6ec51cb385755ae2ac173bed8679abc0db2a23ebafb1e052c8f7578ae270b69` |

`Promote validated image tags` ran `docker buildx imagetools create` over
`${image}@${STANDARD_DIGEST}` with `STANDARD_DIGEST=sha256:f007b57f...`, so
promotion retagged the tested index rather than rebuilding. Confirmed
independently against the registry after publication: `v1.8.1` and `latest`
both resolve to `sha256:f007b57f...`, with the two per-architecture manifests
above. No image was built between the scan and the tags.

### What the gate actually checked on that digest

`Test staged hosted scan` pulls the staged digest and scans through the
offline hosted-worker boundary -- no network, read-only source and advisories.
On **both** architectures:

- all four components reported findings: `{'gitleaks': 1, 'grype': 61, 'semgrep': 1, 'kics': 4}`, twice per architecture (serial and parallel);
- serial and parallel hosted scans preserved the complete finding identity multiset;
- a Python-only read-only checkout reported dependency vulnerabilities;
- missing and stale advisory data were **refused** without a clean report, for both a missing database and a `1ns` maximum age.

`Release Security Scan` and both native builds also passed, and
`Update GitHub Release` published the release only after all of them.

### The defect this gate exposed first

The previous attempt, run
[38095674451](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/38095674451),
failed `Test staged hosted scan` on both architectures **after every assertion
above had passed**. The entrypoint proof seals its `control/` directories at
`0555` holding a `0444` `job.json` so the container under test cannot tamper
with its own control record. `docker.yml` redirects that output to the
workspace; `release.yml` set no such variable, so the proof landed inside the
script's `mktemp -d`, the `EXIT` trap's `rm -rf` could not unlink it, and bash
took the trap's status as the script's. A clean scan exited 1.

Fail-closed behaved correctly: `Promote validated image tags` and
`Update GitHub Release` were skipped and nothing was published.
[#169](https://github.com/sourcebastion/sourcebastion-scanner/pull/169)
restores the owner write bit inside the private scratch tree before removing
it, keeps cleanup from changing the verdict in either direction, and carries
an executable case that fails both with the old trap and with the restore
deleted. Run 38101710508 contains **zero** `cannot remove` lines.

Worth recording as a review lesson: cleanup ran outside the evidence the
checks produced, so a passing scan and a failing job looked identical from
inside the script. The negative case now has a positive one -- the temporary
tree must be gone and the exit status must be the scan's.

## What this does not establish

Release evidence establishes that the published image is the tested image. It
does not establish the items [#159](https://github.com/sourcebastion/sourcebastion-scanner/pull/159)
itself lists as still open: accepted S02-S04 integration, reviewed native
release evidence beyond the release gate, cumulative compressed growth against
the frozen S01 baseline, and distribution closure including the S01
rpds/libgcc finding. Those belong to
[S07 #94](https://github.com/sourcebastion/sourcebastion-scanner/issues/94)
and [M049 #164](https://github.com/sourcebastion/sourcebastion-scanner/issues/164).

Local results in this repository are measured on a macOS checkout where 109
tests fail for unrelated reasons -- 105 npm, yarn and pnpm composition and
vendored Node helper expectations, plus four needing `setuptools` in the local
environment. They fail identically on `main`. The host resource driver cannot
run here at all: it requires a Linux cgroup v2 host, and Docker Desktop cannot
provide local host cgroup acceptance.

The release v1.8.1 is cited as evidence that the published image is the tested
image. No production activation, deployment, customer route or M046 closure is
part of this ledger.
