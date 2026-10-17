# M049 S03: Detect bundled-library drift

## Tasks

- [ ] **T01: Compare both musllinux runtime wheel closures to reviewed bytes.**
  Initial implementation is ready for cross-review. The existing
  `scanner_artifacts.py verify-dependencies` checks the complete resolved
  Semgrep/runtime closure, then compares every separately vendored shared
  library against `.github/bundled-native-libraries.json`. It refuses changed
  wheel identity/version/digest, library paths, sizes and digests. It examines
  previously unseen distributions too; extension modules themselves are outside
  this separately vendored-library set. No ZIP member is extracted or executed.
- [ ] **T02: Bind reviewed notices and exact source coverage.** Remains open
  with S01/S02; a byte digest or compiler string is identification, not source
  provenance. Confirm libelf's actual version from its source/package binding.
- [ ] **T03: Surface proposed changes in the weekly candidate PR.** The current
  proposer calls the existing dependency verifier, so drift now stops before
  reviewed pins are written. It prints added/removed/changed paths and digests.
  A candidate report/PR that preserves that refusal while exposing the proposed
  set for notice/source review is still needed; do not automatically accept a
  newly observed manifest.

## Current checks (2026-10-17)

All 70 hash-locked runtime wheels for each architecture were downloaded with
the existing target marker/ABI options and checked by the existing dependency
closure verifier. Each architecture has 19 separately vendored library files:
16 in Semgrep 1.180.0 and one each in cryptography 50.0.2, pydantic-core 2.50.1
and rpds-py 2026.9.1. The baseline binds actual pip-selected cp311-abi3
cryptography wheels, not the other compatible cp39 wheels.

The original [ARM64 image observation](../M046/S06-bundled-natives-arm64.json)
was Semgrep 1.179.0/pydantic-core 2.46.5 and remains historical. Current compiler
strings identify different GCC families: Semgrep's 15.2.0, cryptography's
14.2.0 and rpds/pydantic's 12.4.0. These are not interchangeable source claims.
The [Semgrep release Dockerfile](https://github.com/semgrep/semgrep/blob/v1.180.0/Dockerfile)
uses Alpine 3.23 for Semgrep, but that does not establish the other wheels'
build environments or all patches used for their runtime copies.

Focused tests cover unchanged bindings, added/removed/renamed libraries,
same-size changed bytes, a new vendor outside known packages/directories,
wrong architecture, duplicate/non-ELF members and refusal through the existing
dependency-verification entry point. This is drift detection only; no image was
built, altered, executed or published and no source mirror was published.
