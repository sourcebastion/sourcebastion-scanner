# M049 S03: Detect bundled-library drift

Accepted for v2.1.2; [release and integration evidence](ACCEPTANCE.md).

## Tasks

- [x] **T01: Compare both musllinux runtime wheel closures to reviewed bytes.**
  #202 merged the guard into existing dependency verification. Each architecture
  has 19 separately vendored libraries in the complete 70-wheel locked runtime
  closure. New distributions/vendors are inspected too. The guard rejects
  changed owner/version/wheel identity, paths, sizes or library digests.
  ZIP data is inspected without importing or executing candidate code.
- [x] **T02: Bind reviewed notices and exact source coverage.** Every reviewed
  native byte set has retained original texts and source/build references.
  Copyleft source and recipes were published and anonymously checksum-verified.
  Libelf was confirmed as 0.194 against official Alpine code/read-only/build-ID
  sections. Both exact staged release architectures checked actual installed
  native bytes and source directions before publication.
- [x] **T03: Surface proposed changes in the weekly candidate PR.**
  [Main run 39109145980](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/39109145980)
  passed publisher, wheel-hash and closure verification and opened
  [draft #206](https://github.com/sourcebastion/sourcebastion-scanner/pull/206)
  for Semgrep 1.181.0. Its separate observation reports both architectures;
  the release baseline, notices and source pins were untouched.
  [Strict verification 39109214153](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/39109214153)
  rejected the unreviewed wheel/owner bindings. No candidate was accepted.

## Qualification

The released baseline is Semgrep 1.180.0, cryptography 50.0.2, pydantic-core
2.50.1 and rpds-py 2026.9.1. The manifest records actual pip-selected
cp311-abi3 cryptography wheels. The older M046 ARM64 image record remains
historical, not evidence substituted for the current release.

The real 1.181.0 proposal has 19 libraries per architecture with no added,
removed or changed library bytes; its Semgrep wheel/version/path bindings
changed and still require review. Strict release commands cannot opt into
proposal mode. The observation never replaces the release baseline.

Focused tests cover synthetic additions/removals/renames, same-size byte
changes, new vendors outside known packages, wrong architecture, duplicate and
non-ELF members, changed/missing notices, protected-baseline refusal and
candidate observation followed by strict release refusal. Native runtime checks
account for standard wheel purelib/platlib spreading without changing bytes.
All 116 focused tests and full native CI39107423289 passed. The normal release
workflow then checked both exact staged architectures and published v2.1.2.
