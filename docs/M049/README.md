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

- [**S01: Notices and written source directions in the image**](S01-PLAN.md).
  Version-specific texts, native-byte bindings and Docker inclusion merged in
  [#203](https://github.com/sourcebastion/sourcebastion-scanner/pull/203).
  Source directions now name the published immutable mirror. Actual released-image
  verification remains open until v2.1.2 passes the normal release workflow.
- [**S02: Digest-verified source mirror**](S02-PLAN.md). Source and recipe
  archives were reviewed and published by [main run 39106864706](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/39106864706),
  including a successful anonymous digest-verified download. The immutable source
  manifest is `sha256:88740e3f4ef899fc63aad828497bf0f1cf535fb1878098c66a4ca3a768a2dbf2`.
  Recipe/source coverage is separate from historical build-container attestation.
- [**S03: Drift detection and architecture evidence**](S03-PLAN.md). Started:
  #202 is reviewed and merged. Current musllinux wheels are bound per architecture; existing dependency
  verification refuses additions, removals or changed owner/wheel/library bytes.
  Notice coverage merged in #203; the reviewable weekly candidate diff is
  prepared in #205. Released-image acceptance remains required.

Budget: **one engineering day total**, approved by the owner on 2026-10-17.
This includes work already performed, design, implementation, tests, evidence,
reviews and verification. The clock does not restart for a split or scope change.
If there is no accepted shipped result at **half an engineering day**, stop and
return a specific owner decision instead of adding prerequisites. The first
increment is the existing artifact verifier's bundled-set guard; source publication is now verified; released-image acceptance is still pending.

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

Source publication and source/notice review are verified. Final acceptance still
requires released-image checks and exercising the weekly proposer. All three
owner-scope outcomes must be recorded before closing #164.
The current wheel evidence is not a fresh published-image observation and does
not establish provenance or discharge redistribution obligations by itself.
