# Version and release management

SourceBastion Scanner uses semantic versions, but releases are deliberately
manual. A release changes public container tags and therefore requires both a
reviewed source change and a second-person approval.

## Prepare a release

1. Open a pull request that updates `VERSION` to the next `MAJOR.MINOR.PATCH`
   value and adds a useful entry to `CHANGELOG.md`.
2. Merge only after all required checks and the independent review pass.
3. From `main`, dispatch the `Release` workflow with the exact version prefixed
   by `v` (for example `v1.7.31`).
4. A different named reviewer approves the protected `release` environment.

The workflow rejects a version that does not match `VERSION`, a non-semantic
version, a dispatch outside `main`, or a published tag. It creates a draft
release, builds all five variants under run-scoped staging tags, attaches SBOM
and provenance records, and scans the standard image by digest. Only after
every build and scan succeeds does it promote the full-version, full-commit,
and compatibility tags and publish the GitHub release.

## Tag policy

- Full semantic tags such as `v1.7.31` and full commit-SHA tags are immutable.
- `latest`, `slim`, `micro`, `thin`, and `semgrep` are compatibility pointers
  that move only when a reviewed release succeeds.
- A failed workflow may leave a draft release and run-scoped staging images.
  Re-run the failed workflow from the same `main` commit: the workflow resumes
  only a matching draft and never moves or reuses a published full-version tag.

Verify a released image with:

```bash
gh attestation verify \
  oci://ghcr.io/sourcebastion/sourcebastion-scanner@sha256:<digest> \
  --repo sourcebastion/sourcebastion-scanner
```
