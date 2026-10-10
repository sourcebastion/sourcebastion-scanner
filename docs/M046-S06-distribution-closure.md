# M046 S06 distribution closure: bundled native libraries

Status: **open, and wider than recorded.** This document is the evidence the
S06 runbook asks for -- the actual bundled bytes, identified and bound to
digests. It is **not a licence clearance**, and it does not close S06.

The runbook's requirement is explicit: *"an APK or wheel hash and an SPDX label
do not resolve it. Inspect the actual current wheel versions and `.libs`
contents, identify each bundled native library's publisher/source, and bind any
clearance to those bytes. If closure is missing, S06 release acceptance remains
blocked."*

Retained evidence: [`docs/M046/S06-bundled-natives-arm64.json`](M046/S06-bundled-natives-arm64.json).

## What S01 recorded, and what is actually shipped

S01 left open "the musl rpds bundled `libgcc_s.so.1` origin/notices/source
obligation". That names one library in one package. The published image carries
**19 distinct vendored native libraries across four packages**, plus Alpine's
own `libgcc_s.so.1`.

Observed on 2026-10-10 in `ghcr.io/sourcebastion/sourcebastion-scanner:latest`
(ARM64), with `cryptography 50.0.2`, `pydantic_core 2.46.5`,
`rpds_py 2026.9.1` and `semgrep 1.179.0`:

| package | vendored libraries |
| --- | --- |
| `semgrep/bin/libs` | libbz2, libcrypto, libdw, libelf, libev, libfts, libgcc_s, libgmp, liblzma, libpcre2-8, libssl, libstdc++, libtree-sitter, libunwind, libz, libzstd |
| `rpds_py.libs` | libgcc_s |
| `pydantic_core.libs` | libgcc_s (**byte-identical to `rpds_py`'s**) |
| `cryptography.libs` | libgcc_s (**different bytes again**) |

Four distinct `libgcc_s.so.1` byte-sets ship in one image. `rpds_py` and
`pydantic_core` vendor the same bytes; `cryptography` and `semgrep` each vendor
different ones; Alpine supplies a fifth at `/usr/lib`.

## How `rpds_py` was traced, and why it ships

`rpds-py` appears only in the `semgrep` dependency locks, which initially
suggested it might not reach the runtime image.
`scripts/scanner_artifacts.py`'s `install` defaults to `group='semgrep'`, and
the builder stage installs into the venv without `--group`, so the semgrep tree
is what populates `/opt/venv` -- which the runtime stage copies. Confirmed by
observation rather than inference: the file is present in the published image.

The pinned wheels were fetched and verified against both PyPI and the
repository's 128-hash pin set before inspection:

| wheel | bundled file | bytes | sha256 |
| --- | --- | --- | --- |
| `cp314-musllinux_1_2_x86_64` | `libgcc_s-f685abf1.so.1` | 538,513 | `91a43de5877248a317d14faa35490ef474a1b33a83e235b52fb1eabf7108108e` |
| `cp314-musllinux_1_2_aarch64` | `libgcc_s-0bf60adc.so.1` | 529,921 | `f33db50df5fb0591ee20b789e7f26cb4593e3a36a3dcd45c668d5af03a3f5a87` |

Both report `GCC: (GNU) 12.4.0` and soname `libgcc_s.so.1`, read as data. No
Alpine build marker is present, so these came from the musllinux build
toolchain rather than Alpine's `libgcc` package.

## The upstream SBOM does not cover it

`rpds_py-2026.9.1` ships a CycloneDX 1.5 SBOM at
`dist-info/sboms/rpds-py.cyclonedx.json`. It lists **17 cargo crates** -- the
Rust build dependencies -- and **omits the bundled `libgcc_s.so.1` entirely**.

This is the concrete reason a wheel hash plus an SPDX label is insufficient:
the upstream provenance document does not mention the component that carries
the obligation.

## Identification, not clearance

Licence families below are identification from the library identity, for
scoping. **None of this is a clearance**, and several need a decision rather
than a lookup:

- `libgcc_s`, `libstdc++` -- GCC runtime, GPL-3.0-or-later WITH
  GCC-exception-3.1. Whether redistributing the shared object inside an image
  is covered by the Runtime Library Exception, and what source offer follows,
  is a judgement this document does not make.
- `libgmp` -- LGPL-3.0-or-later (dual GPL-2.0-or-later). Carries an LGPL source
  obligation.
- `libdw`, `libelf` -- elfutils, GPL-3.0-or-later / LGPL-3.0-or-later.
- `libunwind` -- identity ambiguous from bytes alone: LLVM's and nongnu's
  carry different terms, and this needs the actual origin established.
- `libcrypto`, `libssl` -- OpenSSL 3, Apache-2.0.
- `libbz2`, `libev`, `libfts`, `liblzma`, `libpcre2-8`, `libtree-sitter`,
  `libz`, `libzstd` -- permissive families, still requiring notice retention.

## What remains to close this

1. Establish each bundled library's **publisher and source** for the exact
   bytes recorded, not for the library in general.
2. Decide the GCC Runtime Library Exception question for a shared object
   redistributed inside an image, and the source offer that follows.
3. Resolve `libgmp` and elfutils source obligations, which are not discharged
   by notice retention alone.
4. Establish `libunwind`'s actual origin.
5. Record the equivalent evidence for **AMD64**; only ARM64 was observed, and
   at least `rpds_py`'s bytes differ per architecture.
6. Retain notices for every library above, per the runbook.

Until those are answered, S06 release acceptance remains blocked -- and the
scope is four packages and nineteen libraries, not one.

## Tracking

This work is scoped as
[M049 #164](https://github.com/sourcebastion/sourcebastion-scanner/issues/164),
in three slices: notices and a written offer in the image, a source mirror for
the copyleft set, and drift detection with per-architecture evidence.

That milestone takes a deliberately conservative posture. No legal opinion is
sought, so it complies as though the GCC Runtime Library Exception question
resolves against us, because mirroring GCC source costs less than deciding it.
Where a library is dual-licensed with a permissive arm it elects that arm and
records the election.

It also records why no slice removes a vendored binary. The vendoring is
mandated by the wheel platform policy rather than chosen: the same `rpds_py`
version vendors nothing in its manylinux wheel and `libgcc_s` in its
musllinux wheel, because the musllinux whitelist is smaller. A glibc base
would be worse, not better -- semgrep's manylinux wheel vendors 26 libraries
against musllinux's 16.

Provenance is published, which is what makes the work mechanical. Semgrep
builds `semgrep-core` on `alpine:3.23`, so these are Alpine 3.23 packages;
versions read from the shipped binaries match (`gmp 6.3.0-r4`,
`elfutils 0.194-r0`, `zstd 1.5.7-r2`, `libunwind 1.8.1-r0`), and our own base
is Alpine 3.23.6. Corresponding Source is Alpine's `aports` -- APKBUILD,
patches and upstream reference, already assembled.
