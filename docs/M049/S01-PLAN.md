# M049 S01: Retain native-library notices

Accepted for v2.1.2; [release evidence](ACCEPTANCE.md).

## Tasks

- [x] **T01: Retain version-specific license texts and source pointers.**
  `third-party-notices/` contains 15 component/version groups and 30 original
  license/author texts, bound to all 19 vendored files per architecture.
  All texts matched pinned original upstream archives. Source SHA-256,
  APKBUILD/build references, license-file hashes and native hashes are recorded
  in its manifest. Docker copies the directory beside the existing Go notices.
- [x] **T02: Verify notice coverage and drift.** The existing dependency verifier
  rejects uncovered native bytes, missing/changed texts, ambiguous bindings
  and redirected notice paths. Both exact staged image architectures verified
  all 19 installed native records and retained license/source-direction bytes;
  the same immutable index was promoted to v2.1.2.
- [x] **T03: Publish truthful source directions beside the notices.**
  Source publication and anonymous checksum verification passed before
  `SOURCE-AVAILABILITY.md` was changed. The released file names the actual
  immutable OCI source reference and bundle/archive verification commands.

## Identified sources and choices

The BSD elections for libev and zstd are retained. XZ's original summary
identifies liblzma as 0BSD separately from its command-line tools. GCC runtime
coverage remains conservative, without deciding the Runtime Library Exception.

Semgrep v1.180.0 pins tree-sitter **0.26.3**, including its source hash;
Alpine's different tree-sitter package is not substituted as its source.
The x86_64 libelf `.text`, `.rodata` and GNU build-ID sections match official
Alpine `libelf-0.194-r0.apk`, resolving the misleading `1.3.1` string.
Its `.text` SHA-256 is
`29773b7f0405f92b7b71a873aee0c1ba0abce6f32ddaa229e094a7ea5820ae7a`.
ELF inspection reads data and never loads a library.

GCC 12.4.0, 14.2.0 and 15.2.0 remain distinct source identities. Source/recipe
review and its limits are recorded in S02 and the acceptance ledger; a compiler
string alone is not treated as a complete historical build attestation.
