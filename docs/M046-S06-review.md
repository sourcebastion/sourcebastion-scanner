# PR #159 review and corrections

Original review: `bc0adb5afb470ad0b21433ff5bcbd1dd43d90232`, 2026-10-09.
Scope: code quality, maintainer usability, test coverage and S06 status.

## Findings and resolutions

1. **P2 — exit-file visibility was not a stopped-shell handoff.** The shell
   creates the file before completing printf and stopping. An early read could
   see empty bytes; an early CONT could be lost. The driver now waits for the
   second stopped state before reading the exit code and final cgroup counters.
   A delayed-stop regression also refuses counter reads after release.
2. **P2 — OCI builds bypassed the mirror.** Candidate export now receives the
   selected candidate arguments. Baseline export and load independently select
   mirror/upstream references from the baseline checkout's own reviewed pins.
   Tests verify different baseline digests, public token handling, unavailable
   registries, malformed token responses, and fatal version drift.
3. **P2 — Python release preparation left digest pins behind.** Preparation now
   verifies the official index, native manifests and native interpreter configs,
   then updates both pin manifests, the Dockerfile and interpreter version along
   with wheel locks. Release PRs stage both manifests. Tests cover the complete
   version change, digest/size/platform/version failures and preservation of
   reviewed files when registry verification fails.

## Verification and second review

The focused maintenance, mirror, Python release preparation, entrypoint and
release-workflow suites pass: 152 tests. A live read of the official registry
verified the existing Python 3.14.8 index and both native config/manifest chains
against the recorded pins. No version or dependency upgrade was performed.

The second code review confirmed that all cgroup reads precede final release,
Docker wait stdout is parsed independently of stderr, baseline selection keeps
baseline digests, and verification happens before release files are changed.
No additional actionable finding remains in these corrections. Native Linux
end-to-end acceptance still depends on CI for the resulting commit; local
mocked tests do not establish that evidence.

S06 remains implementation in review, not accepted. Issue #93 and PR #159 have
been corrected to reflect this. Required final evidence includes accepted S04
integration, native release/resource results, cumulative compressed growth from
the frozen S01 baseline and distribution closure. See M046-S06-acceptance.md.
