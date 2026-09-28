# Scanner upgrade record — 2026-09-27

KICS v2.2.0 and Semgrep v1.178.0 passed the three-day soak. Their authenticated
GitHub release evidence contained no release assets, so no matching immutable
image digest or package checksum was available. The existing digest-pinned KICS
image and Semgrep 1.176.1 pin remain unchanged until independently verifiable
integrity metadata is available for the exact release artifacts.
