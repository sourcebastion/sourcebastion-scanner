# M049 S02: Source mirror in the existing scanner repository

## Tasks

- [x] **T01: Review source and build-recipe pins.** Five original upstream
  archives cover GMP 6.3.0, elfutils 0.194 and conservative GCC 12.4.0,
  14.2.0 and 15.2.0. Four commit-pinned recipe archives retain Alpine 3.23/
  3.21 APKBUILDs and patches and rust-musl-cross/musl-cross-make inputs.
- [x] **T02: Publish and retrieve by digest.** ORAS 1.3.4 prepares a standard
  OCI layout. Every archive, the deterministic tar and OCI manifest must match
  reviewed pins before the main-only publisher gets package write authority.
  Anonymous re-download must match the pinned tar before success is reported.
- [ ] **T03: Put the available immutable reference beside the objects.** Only
  after T02 succeeds, replace SOURCE-AVAILABILITY.md's pending notice with the
  digest reference and retrieval instructions, then verify both image arches.

## Mechanism, authority and recovery

Use curl, Python's standard tar/hash libraries and ORAS; no new service,
credential, provider or wire contract. `.github/native-source-pins.json` binds
original bytes and component identities. The existing public scanner package
receives a distinct `native-sources-<manifest hash>` tag, never an image tag.
Recipients use the immutable digest. The tar is 319,180,800 bytes, substantially
larger than the scope estimate because three actual GCC families are present.
Original archives are retained compressed and unmodified, with SHA256SUMS.

The prepare job has contents read only, including on pull requests. Only a
main push or main workflow dispatch can enter the separate publisher job,
using the existing repository GITHUB_TOKEN with packages write. It affects
only source artifact tags in the scanner package; it does not modify scanner
binaries, other repositories, hosts or deployment state. The publisher logs
public digests and verifies anonymous access. A failed or interrupted run can
be rerun against the same immutable pins; hash mismatch stops before upload.
Removal of historical artifacts is outside its authority. Missing source,
changed source identity or wider scope goes to the owner.

## Source identification and limits

Semgrep 1.180.0's release Dockerfile uses Alpine 3.23. GMP, elfutils and GCC
15.2.0 recipes are retained from aports cb29f3b; cryptography's Alpine GCC
14.2.0 recipe from 3.21 aports 4d7e25e. Both aports snapshots contain the
original build instructions and patches. Upstream archive digests were checked
against the respective APKBUILD SHA512 sums before recording SHA256 here.
The GCC 12.4.0 archive was checked against GCC's published release SHA512 sum.

The rpds 2026.9.1 release workflow's pinned maturin action selects
rust-musl-cross for musllinux; its retained config selects GCC 12.4.0.
The retained musl-cross-make snapshot includes build scripts and patches.
Pydantic-core and rpds carry identical GCC runtime bytes on each architecture.
Historical wheel build container digests are not established by these
snapshots; do not claim reproducible builds or a complete historical build
attestation from a compiler string. Cross-review must assess correspondence
before treating the mirror as acceptance, rather than treating download
success alone as legal clearance.

The source mirror was published and anonymously re-downloaded successfully in
[main run 39106864706](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/39106864706).
The bundle SHA-256 is `47c099826215dc33520595a9a51d47df05a633078d28adb9cc8ce9680d896d63`;
its OCI manifest is `sha256:88740e3f4ef899fc63aad828497bf0f1cf535fb1878098c66a4ca3a768a2dbf2`.
All 91 Alpine source/patch SHA512 entries and the three GCC release archive
SHA512 lists were independently checked. Released-image qualification remains T03.
