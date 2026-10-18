# M049 S02: Source mirror in the existing scanner repository

Accepted for v2.1.2; [release evidence](ACCEPTANCE.md).

## Tasks

- [x] **T01: Review source and build-recipe pins.** Five original upstream
  archives cover GMP 6.3.0, elfutils 0.194 and conservative GCC 12.4.0,
  14.2.0 and 15.2.0. Four commit-pinned recipe archives retain Alpine
  3.23/3.21 APKBUILDs and patches and rust-musl-cross/musl-cross-make inputs.
  All 91 Alpine source/patch SHA512 entries and the three GCC release archive
  SHA512 lists matched. Original archives remain unmodified.
- [x] **T02: Publish and retrieve by digest.** ORAS 1.3.4 constructed the
  reviewed OCI manifest after archive and deterministic-tar checks.
  [Main run 39106864706](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/39106864706)
  published it through the existing scanner package and anonymously downloaded
  it again, matching the pinned bundle. Changed source or bundle bytes reject
  before publication; an OCI manifest mismatch also stops preparation.
- [x] **T03: Put the available immutable reference beside the objects.**
  The verified reference and download/checksum commands are in the released
  `SOURCE-AVAILABILITY.md`. Both staged architecture checks verified that
  exact file before the unchanged image index was promoted.

## Published identities

- OCI manifest: `sha256:88740e3f4ef899fc63aad828497bf0f1cf535fb1878098c66a4ca3a768a2dbf2`.
- Bundle: `sha256:47c099826215dc33520595a9a51d47df05a633078d28adb9cc8ce9680d896d63`.
- Repository: `ghcr.io/sourcebastion/sourcebastion-scanner`.

The 319,180,800-byte tar retains the nine original compressed archives and
SHA256SUMS. Its size exceeds the initial estimate because three GCC families
are covered. Recipients need no package credentials. The distinct source tag
is never used as an image tag; recipients use the immutable digest.

## Source identification, authority and limits

Semgrep's Alpine 3.23 recipes are retained from aports cb29f3b; cryptography's
Alpine 3.21 GCC recipe from 4d7e25e. Semgrep's GCC 15 runtime code/read-only
data/build IDs match official Alpine 15.2.0-r2 libraries. Cryptography's GCC 14
code, read-only data, unwind and other nonmetadata sections match Alpine
14.2.0-r4; its dynamic/build-ID differences remain explicit.

The rpds 2026.9.1 workflow selects maturin's rust-musl-cross toolchain. The
retained configuration selects GCC 12.4.0; musl-cross-make includes its build
scripts and patches. Pydantic-core and rpds carry identical runtime bytes on
each architecture. These source/recipe bindings do not establish historical
wheel-container digests, binary reproducibility or a legal opinion.

Preparation has contents-read authority, including on PRs. Only the separate
main-only publisher gets existing repository package-write authority. It
changes no scanner binaries, hosts, deployments or other repositories.
Hash mismatch stops; retries use the same immutable pins. Historical source
artifacts are retained. Missing source or wider scope remains owner-only.
