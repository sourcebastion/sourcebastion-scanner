# M052 S04: coherent automated scanner updates

Owner request on 2026-10-19: fix the automated scanner update process so it
updates the required manifests together. Use the existing GitHub Actions bot,
wheel verifier and native manifest; no new service, authority or provider.

**T01:** Reproduce scanner #206's integrity/native build failures. Its Semgrep
1.181.0 locks refer to new wheels, but the native manifest still binds 1.180.0.
All 19 libraries per architecture have identical installed paths, owners, sizes
and bytes; wheel/version metadata and wheel-spreading prefixes differ.

**T02:** Stage the native manifest alongside dependency locks, refreshing only
metadata for identical native sets. Upload, detect and commit that manifest in
the weekly bot PR. Retain strict release checks and draft review for actual
native drift. Verification failures leave candidate outputs unchanged.

**Acceptance:** Regression tests cover metadata refresh on both architectures,
changed bytes/size/path/owner, additions/removals/duplicates, cross-architecture
substitution, notice failure and staged publication. Replay #206's observed
candidate through the updated preparation and strict native verification.
Normal PR/native CI remains required. No environment deployment or source
bundle update is needed for this automation repair.


**T03 (owner revision 2026-10-19):** Separate components before the next release.
Scanner #211 includes Dependabot #197 and the repaired manifests. Publication
run 39334854663 was cancelled before its draft/tag/image existed. Platform
[#481](https://github.com/sourcebastion/sourcebastion-platform/issues/481) owns
organization discovery/config/installation; sourcebastion-action owns runner
orchestration; scanner keeps scanning and report generation. Keep own repository
build/test/release workflows. No provider installation or credentials are moved.
README version/date badges read published releases, excluding the pending VERSION.

**T04 (owner request 2026-10-20):** Make Semgrep failures visible in scanner
stderr: scan start, process exit/timing, stable failure code and counted error
types. Never copy source-bearing raw stderr, error messages or findings into
shared pod logs. Local JSON results remain the findings channel. Strip inherited
Semgrep login/rule/tracing settings and isolate its saved settings/log in a
private temporary directory; use the CE scan engine with explicit local
rule packs, telemetry off and version checking off. Offline hosted scans must
refuse registry fallback when local packs are absent. Kubernetes deny-all egress
and Docker network-none remain the enforcement boundary, independent of flags.
Verify both the version probe and scan subprocess settings, source redaction,
timeout/crash/file-error stderr and the real offline hosted smoke. No coverage,
size-boundary, provider or credential change.
