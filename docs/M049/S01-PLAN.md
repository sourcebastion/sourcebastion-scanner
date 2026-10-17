# M049 S01: Retain native-library notices

## Tasks

- [ ] **T01: Retain version-specific license texts and source pointers.**
  Prepared for the 19 vendored files per architecture, grouped into 15
  component/version directories under `third-party-notices/`. Texts are copied
  verbatim from source archives verified against Alpine's pinned APKBUILD
  SHA-512 values, GCC's release SHA-512 lists, or Semgrep's tree-sitter source
  SHA-256. The notice manifest records source SHA-256, build references and
  license-file digests, binding each native byte set to its retained texts.
  The runtime Dockerfile copies this directory beside the existing Go notices.
- [ ] **T02: Verify notice coverage and drift.** The existing dependency verifier
  requires every bundled byte set to have an unchanged retained license and a
  pinned upstream source reference. New native bytes, missing/changed license
  text, ambiguous bindings and symlinked notice paths refuse. Qualification of
  the actual resulting image remains required after review.
- [ ] **T03: Publish truthful source directions beside the notices.** Open with
  S02. `SOURCE-AVAILABILITY.md` states that the controlled source mirror and
  complete corresponding-source qualification are pending; it is not a written
  offer pointing at an anticipated or nonexistent artifact. Replace that status
  with the verified immutable mirror location/download command when available.

## Identified sources

The permissive-arm elections for libev and zstd are recorded alongside their
original terms. XZ's licensing summary identifies liblzma as 0BSD separately
from its command-line tools. GCC runtime coverage remains conservative.

The v1.180.0 Semgrep source explicitly builds tree-sitter **0.26.3**, including
the pinned source tarball hash, rather than Alpine 3.23's tree-sitter 0.25.10.
That fixes the source reference for `libtree-sitter.so.0.26`.

For libelf, the x86_64 wheel's `.text`, `.rodata`, GNU build ID and all other
sections except `.dynsym`, `.dynstr` and `.dynamic` match the official Alpine
`libelf-0.194-r0.apk` member `usr/lib/libelf-0.194.so`. The `.text` SHA-256 is
`29773b7f0405f92b7b71a873aee0c1ba0abce6f32ddaa229e094a7ea5820ae7a`.
This resolves the misleading embedded `1.3.1` string; it is not the libelf
package version. Comparison used pyelftools on bytes, without loading a library.
The dynamic-section differences remain explicit; no binary reproducibility or
complete build-provenance claim follows.

The source references distinguish GCC 12.4.0, 14.2.0 and 15.2.0. Exact compiler
image/build-recipe/patch lineage, especially the GNU 12.4.0 runtime copies,
still needs source-mirror review; a compiler string alone does not close S02.
