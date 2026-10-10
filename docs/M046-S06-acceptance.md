# M046 S06 acceptance ledger

Status: implementation is largely in place and in review on
[#159](https://github.com/sourcebastion/sourcebastion-scanner/pull/159).
S06 is **not accepted**: its own acceptance sentence requires exact-head CI and
release evidence, and several items below are open for reasons no merge
addresses.

Tracking: [S06 #93](https://github.com/sourcebastion/sourcebastion-scanner/issues/93).
Canonical scope: [M046 #88](https://github.com/sourcebastion/sourcebastion-scanner/issues/88).

This file records what the slice establishes and what it does not, the same way
[S04's ledger](M046-S04-acceptance.md) does. It is not a release, deployment or
milestone closure.

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
| Coordinate with [#54](https://github.com/sourcebastion/sourcebastion-scanner/issues/54) without assuming its older architecture | **open** | #54 is open. This slice reuses the verified snapshot rather than a database in every image, which is the coordination S06 asks for, but #54 records no agreed position yet |
| Numeric budgets pass on native hardware | **open** | Needs the exact-head native run; see below |
| Exact-head CI and release evidence | **open** | The requirement S06 names last, and the one that cannot be satisfied from a developer checkout |

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

## What this does not establish

The exact-head native run is the gate S06 names, and no local result
substitutes for it. Also open, and listed by #159 itself: accepted S02-S04
integration, reviewed native release evidence, cumulative compressed growth
against the frozen S01 baseline, and distribution closure including the S01
rpds/libgcc finding.

Local results in this repository are measured on a macOS checkout where 109
tests fail for unrelated reasons -- 105 npm, yarn and pnpm composition and
vendored Node helper expectations, plus four needing `setuptools` in the local
environment. They fail identically on `main`. The host resource driver cannot
run here at all: it requires a Linux cgroup v2 host, and Docker Desktop cannot
provide local host cgroup acceptance.

No production activation, release, deployment or milestone closure is part of
this ledger.
