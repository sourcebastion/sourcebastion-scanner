# M049 acceptance: v2.1.2

Accepted 2026-10-18 against the released image and source mirror. This closes
[owner scope #164](https://github.com/sourcebastion/sourcebastion-scanner/issues/164)
for the current scanner distribution, without changing its native binaries.

## Released identities

[Release v2.1.2](https://github.com/sourcebastion/sourcebastion-scanner/releases/tag/v2.1.2)
was published at **2026-10-18 08:30:51 UTC** from source
`fb81549822f6ab323f758bd3bf7db8234e564b7e`.
[Release run 39109155329](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/39109155329)
succeeded, including supply-chain verification, both native validation suites,
both exact staged hosted scans, release security scan and normal promotion.

| Artifact | Immutable digest |
| --- | --- |
| Scanner index | `sha256:f4d60f4594698f5e799badaa13804be8a296c5028e7b1efab86bb6fee091ea64` |
| Linux AMD64 manifest | `sha256:92b4892df0eecac764e05f90ef73b46a74a65bb54fd282bcb39771b9582705be` |
| Linux ARM64 manifest | `sha256:8d8f21877e195673f9773c19211169471f4b2bfd5154d52b32d4ba4cb2288739` |
| Source OCI manifest | `sha256:88740e3f4ef899fc63aad828497bf0f1cf535fb1878098c66a4ca3a768a2dbf2` |
| Source tar | `sha256:47c099826215dc33520595a9a51d47df05a633078d28adb9cc8ce9680d896d63` |

Anonymous registry reads of `v2.1.2`, `latest` and the source-SHA image tag
returned HTTP200 with the **same index digest** and platform manifests as the
staged image. The source manifest was also anonymously retrievable and names
the reviewed tar layer. No prior image digest was altered.

## Requirement-by-requirement acceptance

| Slice | Required behavior | Actual evidence |
| --- | --- | --- |
| S01 | Retain every bundled library's notice, source pointer and download directions in both image architectures | Fifteen component/version groups contain 30 original license/author files. The notice manifest covers all 19 native records per architecture. Both staged jobs printed `19 bundled native files, retained licenses and source directions verified` against the exact index above, before promotion. |
| S02 | Reviewed copyleft source and build recipes are retrievable from the existing registry and reject wrong digests | [Main publication 39106864706](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/39106864706) prepared the pinned OCI layout, published and anonymously downloaded the tar, then verified its exact SHA-256. Negative tests reject changed source/cache/bundle bytes; manifest mismatch stops before the publisher job. Source directions were updated only after successful publication. |
| S03 | Per-architecture evidence, refusal on unreviewed native changes, reviewable weekly candidate | The reviewed native manifest and both real staged checks bind the actual image. Synthetic additions/changes fail strict tests. [Weekly run 39109145980](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/39109145980) opened [draft #206](https://github.com/sourcebastion/sourcebastion-scanner/pull/206) with both architecture observations; [strict candidate CI39109214153](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/39109214153) refused its changed bindings. |

The staged native/notice checks ran at **08:25:33 UTC on AMD64** and
**08:25:38 UTC on ARM64**. Each compared installed owner, version, path, size
and digest with the reviewed wheel manifest, retained original license hashes
and the exact `SOURCE-AVAILABILITY.md`. Standard wheel `.data/purelib` and
`.data/platlib` installation spreading is accounted for; native bytes are not
rewritten. Both full hosted scan jobs succeeded afterward.

All engine/rule/runtime/base pins, dependency locks and product source are
unchanged from v2.1.1. Existing Go notices and Python-package notices remain.
No library was removed, substituted or modified to simplify distribution.

## Source and notice review

All 30 texts matched their pinned original upstream archives. All 91 Alpine
source/patch SHA512 entries and all three GCC release archive SHA512 lists
matched the retained bytes. The nine compressed archives comprise five
upstream source families and four recipe snapshots, with SHA256SUMS in the
319,180,800-byte deterministic tar.

- GMP 6.3.0 and elfutils 0.194 use the retained Alpine 3.23 aports recipes.
  Libelf's code, read-only data and GNU build ID match official 0.194-r0,
  resolving the misleading embedded `1.3.1` string.
- Semgrep's GCC15 runtime code/read-only data/build IDs match Alpine
  15.2.0-r2; cryptography's GCC14 code/data/unwind and other nonmetadata
  sections match Alpine14.2.0-r4. Cryptography's dynamic/build-ID differences
  remain explicit; whole-binary equality is not claimed.
- Rpds' release workflow selects the rust-musl-cross toolchain whose retained
  config selects GCC12.4.0. Its musl-cross-make scripts/patches are retained.
  Pydantic-core and rpds have identical GCC runtime bytes per architecture.
- Semgrep's actual tree-sitter pin is 0.26.3. BSD elections for libev/zstd and
  the liblzma 0BSD distinction are recorded beside the original terms. GCC
  source coverage is conservative, without deciding its Runtime Library Exception.

Review records: [#203](https://github.com/sourcebastion/sourcebastion-scanner/pull/203#issuecomment-6246758445),
[#204](https://github.com/sourcebastion/sourcebastion-scanner/pull/204#issuecomment-6247017588),
[#205](https://github.com/sourcebastion/sourcebastion-scanner/pull/205#issuecomment-6247315081).
The owner explicitly authorized self-review/self-merge because Claude was
unavailable. All required PR checks passed before each merge.

## Drift demonstration and scope

The real weekly proposal selects Semgrep1.181.0. Both architectures still
have 19 libraries and unchanged library bytes, but wheel/version/path bindings
changed. The separate proposal file reports them; native release baselines,
notices and source pins stayed untouched. It remains a draft for a later engine
upgrade review. Its expected strict refusal is evidence of M049's guard,
not a request to accept that upgrade or relax verification.

All 116 focused artifact/lock/native/notice/source/release tests passed, as did
[full native PR CI39107423289](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/39107423289).
The exact public release was then independently checked by the ordinary staged
release jobs above. No additional controller or qualification service was built.

Acceptance covers this distributed scanner's separately vendored library set
and the source/notice work requested in #164. It is not a legal opinion,
reproducible-build claim or historical wheel-container attestation. Alpine's own
system packages rely on Alpine's source/notice channels, as the image directions
state. Older M046 image observations remain historical; no host deployment,
production change or customer-license-scanning feature is part of this release.
