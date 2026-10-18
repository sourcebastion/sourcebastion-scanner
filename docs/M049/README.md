# M049: Distribution closure for bundled native libraries

[Owner scope and decisions: scanner #164](https://github.com/sourcebastion/sourcebastion-scanner/issues/164).

**Complete for [v2.1.2](https://github.com/sourcebastion/sourcebastion-scanner/releases/tag/v2.1.2),
published 2026-10-18.** [Acceptance and immutable identities](ACCEPTANCE.md).

The distributed scanner image retains bundled-library licenses and source
directions. The conservative copyleft source set is publicly retrievable by
digest from the same GHCR package. Native dependency changes require review.
No scanner engine pin or shipped native binary was modified or removed.
Customer license-scanning features, legal opinions, new providers and host or
production deployment changes remain excluded.

## Accepted slices

- [S01: Notices and source directions in the image](S01-PLAN.md): all 19
  separately vendored native files on each architecture have retained notices
  and source pointers; both released architectures were checked.
- [S02: Digest-verified source mirror](S02-PLAN.md): original source and build
  recipes for GMP, elfutils and the three observed GCC families were reviewed,
  published and anonymously retrieved with matching digests.
- [S03: Drift detection and architecture evidence](S03-PLAN.md): strict release
  verification checks both architecture baselines; the weekly proposer produced
  a real draft observation and strict verification refused its unreviewed bindings.

## Budget

The owner approved **one engineering day total** on 2026-10-17, including prior
work, design, implementation, tests, evidence, review and verification. Splits
or scope changes do not restart the clock. The stop rule was half an engineering
day without an accepted shipped result. The initial increment was the existing
artifact verifier's bundled-set guard in #202; the final released-image and
source acceptance is recorded here, without resetting that budget.

## Trust, authority and recovery

Repository maintainers, reviewed artifact/source pins, upstream publisher
verification, GitHub/GHCR and standard OCI digest verification are trusted.
The verifier reads hash-locked wheel ZIP data without executing candidate code.
The separate source publisher uses a main-only workflow and the existing
repository token to publish source artifacts in the existing scanner package.
The existing bot workflow proposes dependency changes; it does not approve or
merge them.
No new service, controller, provider or credential was introduced.

On native or source drift, verification reports the differences and stops.
The release baseline, notices and source pins stay unchanged until reviewed
together. Source publication and anonymous retrieval precede updating the
image's download directions. Retain immutable source artifacts with their
scanner releases. Missing provenance or broader scope remains an owner decision.

This records source/recipe coverage and actual image retention, not a legal
opinion, reproducible build or historical wheel-container attestation. The older
M046 ARM64 observation remains historical; old image digests were not altered.
