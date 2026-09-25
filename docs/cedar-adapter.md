# Optional standalone Cedar adapter (M042)

The scanner's PLAN-09 policy remains the default. The Cedar engine is developed and released by [`sourcebastion-policy-engine`](https://github.com/sourcebastion/sourcebastion-policy-engine), not imported into the scanner's legacy policy module.

Set `policy_mode: shadow` to compare decisions without changing the PLAN-09 exit code, or `policy_mode: cedar` to enforce the standalone engine's 0/1/2 pass/fail/error mapping. Both modes require `cedar_policy_bundle`, `cedar_policy_binary` and `cedar_binary_sha256` in the scanner config. The last field is the SHA-256 of the exact local binary. The adapter also requires engine version `0.1.0`; use the signed release/checksum provenance appropriate for your environment. The SHA-256 check identifies bytes but cannot authenticate who supplied a guardrail bundle.

The bundle file is local JSON containing exactly `{"bundles": [{"id": "...", "policies": [{"id": "...", "source": "..."}]}]}`. A caller that needs an organization guardrail must assemble and protect the complete bundle file. A repository-controlled workflow can omit an organization policy; this adapter cannot detect that without an authenticated external binding.

The adapter summarizes all post-ignore-suppression findings before the display severity filter. It sends counts only—no raw finding, source text, secret match, path, or credential—and declares protocol and schema version `1` with profile `scan-gate.v1`. It refuses missing or mismatched binaries, malformed bundles, engine timeout, malformed result, and result/exit disagreement. In Cedar mode these are exit 2 and cannot produce a green gate. In shadow mode they are recorded as parity mismatches, but the legacy exit remains authoritative. The scanner writes a versioned sibling artifact named `<output filename>.policy-result.json` when an output path exists; it does not change the existing findings artifact shape.

Rollback is `policy_mode: legacy` (or omit `policy_mode`). This does not change the Action or hosted platform policy. The hosted platform must reconstruct its own trusted full snapshot, choose branch/dismissed/resolved/suppressed semantics, and own its verdict.

For an integration proof with a locally built or downloaded standalone engine, set `SOURCEBASTION_POLICY_ENGINE_BINARY` to the exact binary path and `SOURCEBASTION_POLICY_ENGINE_BUNDLE` to the local bundle file, then run `python3 -m pytest -q tests/test_cedar_adapter.py tests/test_cedar_plan09_parity_live.py`. The live tests scan clean, blocked and warning fixtures through `SecurityScanner`, read the sibling policy artifact, and compare 14 supported PLAN-09 rule cases with exact Cedar IDs. Without those environment variables they are skipped; normal unit tests remain independent of the engine repository.

The `cedar-packaged-adapter` workflow additionally builds this scanner as a wheel, installs it outside the source tree, and runs clean/blocked/warning, malformed-policy, shadow-mismatch, and legacy-rollback artifact proof against a commit-pinned standalone engine on native Linux amd64 and arm64. It also runs the 14-case PLAN-09 parity corpus from the installed wheel. It does not bundle Cedar into the scanner package or change its default mode.

## M043 v2 snapshot adapter

The optional v2 adapter counts complete post-ignore findings by category,
severity, and new/existing cohort. It normalizes explicit scanner categories to
the same gate rows as hosted persistence, including secret-detection, static
analysis, dependency scanning, and container-image aliases. Unknown categories
remain Other unless explicit CVE metadata identifies the finding; a scanner
name alone does not grant a category. This prevents a local gate from silently
using a different row than the hosted gate for the same finding. The platform's
commit-pinned cross-consumer CI compares their full snapshot digests. Container
image findings also retain a distinct `container` category in the serialized
scan artifact; they are not rewritten as dependency findings before hosted
ingestion. The adapter is opt-in for callers that supply a trusted baseline;
legacy and Cedar v1 rollback remain available until a separate CI cutover.
It is intentionally a standalone integration surface and is not yet reachable
through `SecurityScanner` or the CLI. The non-live v2 conformance tests enforce
snapshot validity and the negative protocol cases; live execution remains opt-in.

Do not connect the v2 adapter to `SecurityScanner` or the CLI until both of the
following are defined and reviewed:

1. an authenticated baseline-construction path that obtains the protected ref or
   prior complete scan from a trusted hosted source, rejects fetch/verification
   failures, and validates the baseline digest without treating that digest as
   proof of origin; and
2. an explicit consumer trust boundary that defines who may supply the v2
   binary and bundle, how their provenance is authenticated, and which CI or
   hosted consumer may enforce the result.

Before that enforcement cutover, operators must record and verify trusted
provenance for the exact v2 binary and bundle bytes: build or download them only
from the protected engine release flow, verify the release signature and
checksum against the pinned source commit and published digest, retain the
release approval/attestation with the scan configuration, and regenerate the
bundle from that reviewed source when it changes. A locally built binary is
acceptable only for shadow/integration testing, never enforcement. SHA-256
pinning confirms only that the bytes are unchanged; it does not establish who
built them, from which source, or with whose approval.
