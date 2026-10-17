# M049: Distribution closure for bundled native libraries

[Owner scope and decisions: scanner #164](https://github.com/sourcebastion/sourcebastion-scanner/issues/164).

Outcome: the distributed scanner image retains the required bundled-library
notices and source directions, with retrievable, digest-verified source for the
conservative copyleft set. Candidate changes cannot silently alter that set.
No shipped binary is modified or removed. Customer license scanning, legal
opinions, new providers and production changes are excluded.

Use the existing pinned wheel downloader, Python ZIP/hash inspection, Docker
COPY convention and existing OCI mirror tooling. No new service or controller.
The owner elected permissive license arms where offered and conservative source
coverage for GCC; these are recorded scope decisions, not a legal clearance.

## Current work

- **S01: Notices and written source directions in the image.** Open. Bind them
  to current bytes, not the older ARM64-only observation. Do not publish an
  offer that points to a source mirror which does not exist.
- **S02: Digest-verified source mirror.** Open. Include the appropriate upstream
  sources, build scripts and patches for each actual compiler/library lineage.
  Do not equate an Alpine version match with complete build provenance.
- [**S03: Drift detection and architecture evidence**](S03-PLAN.md). Started:
  current musllinux wheels are bound per architecture; existing dependency
  verification refuses additions, removals or changed owner/wheel/library bytes.
  Notice coverage and a reviewable weekly candidate diff remain open.

Budget: **one engineering day total**, approved by the owner on 2026-10-17.
This includes work already performed, design, implementation, tests, evidence,
reviews and verification. The clock does not restart for a split or scope change.
If there is no accepted shipped result at **half an engineering day**, stop and
return a specific owner decision instead of adding prerequisites. The first
increment is the existing artifact verifier's bundled-set guard; no image/source
publication has been performed.

## Trust, effects and recovery

Existing artifact pins and publisher verification remain authoritative inputs.
Pip downloads only hash-locked wheels; ZIP inspection never imports or runs
their code. This guard owns comparison against the reviewed manifest and can
stop the existing verifier/proposer. It cannot change pins, release an image,
publish source, change credentials or authorize a license/source claim.

On drift, the verifier reports removed/changed and added/changed paths/digests,
then stops. A reviewer updates the manifest only alongside the appropriate
notices/source review. The old baseline stays unchanged on failure. Missing
provenance or broader scope/budget decisions go to the owner; they do not
silently become another implementation slice.

## Acceptance

No M049 slice is accepted yet. All three owner-scope outcomes must be recorded
against the released image and source availability before closing #164.
The current wheel evidence is not a fresh published-image observation and does
not establish provenance or discharge redistribution obligations by itself.
