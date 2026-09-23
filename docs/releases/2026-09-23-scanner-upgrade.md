# Scanner upgrade record — 2026-09-23

Gitleaks and Grype passed the three-day soak and now use authenticated release
archives and GitHub API SHA-256 digests before extraction. The verified
Gitleaks archives cover x64 and arm64 across standard, slim, and thin images;
the micro image retains its existing x64 architecture. Verified Grype archives
cover amd64 and arm64 in the same variants, with amd64 in micro and self-scan.

The self-scan reads these reviewed values from
`.github/scanner-versions.json`. Its unchanged workflow validates every value
before exposing an allowlisted step output, so future maintenance PRs can
refresh scanner pins without modifying executable workflow code.

KICS v2.2.0 and Semgrep v1.177.0 also passed the soak, but their GitHub release
evidence contained no matching immutable image digest or package checksum.
Their existing pins remain unchanged until trustworthy integrity metadata is
available.
