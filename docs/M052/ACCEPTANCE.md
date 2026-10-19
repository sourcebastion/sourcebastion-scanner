# M052 scanner acceptance

Status: implementation tested locally; release and live activation pending.

- 90 existing/extended scanner, parallel-execution and incremental-contract
  checks pass. Thread barriers prove ten components overlap; configured result
  ordering, bounded admission and failure cleanup remain covered.
- The common `configured_scanner_concurrency` reader defaults to ten, accepts
  the descriptive `SOURCEBASTION_MAX_CONCURRENT_SCANNERS=1..10` and preserves an
  explicit old-name limit as a deprecated fallback for one migration cycle.
- Existing native AMD64/ARM64 hosted qualification now compares serial and
  ten-concurrency execution against the same immutable source/advisory inputs.
  These runs, publication and hosted activation are not claimed complete here.
- Only enabled available scanner components execute. This is per-source tool
  concurrency, not ten simultaneous repository jobs or a measured speedup.
