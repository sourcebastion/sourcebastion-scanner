# Native AMD64 diagnostic evidence

`native-amd64-2026-10-06.tar.gz` retains 300 synthetic-corpus runs: 100 stock
Syft, 50 cdxgen with prepared bundled runtime, 100 SCALIBR and 50 Syft projection.
It contains raw tool JSON where available, stdout/stderr, file/process/network
traces, reports, digest manifest, measured source snapshots and the prepared
cdxgen application digest manifest. It contains no tool binaries or customer data.

Verify the archive against `SHA256SUMS`, then verify extracted regular files
against `manifest.json`. Paths are relative; no symlinks are stored in the archive.
The archive is generated with fixed tar metadata and gzip timestamp. Traces retain
evaluator paths and diagnostics; they do not establish production isolation.

The measured corpus source digest is
`6e747cc2b359ee6e8e41dda65d6865cf46eaf3cc7fcb44dc394068ab3ab04e17`.
Formatting afterward preserves exactly the same 50 inputs and expectations.
The first Syft pass predates recording runner SHA256/full argument tracing;
do not claim this archive proves final-head benchmark acceptance. See
[comparison.md](../comparison.md) for interpretation and remaining review gates.

Local verification of the final evaluation code: 21 focused checks, including
two native namespace proofs; scanner regression 1,218 passed / 97 skipped, zero
failures on Python 3.13.5. Skips include absent scanner binaries/live integrations;
this is not native scanner-image Python 3.14 or ARM64 candidate acceptance.
