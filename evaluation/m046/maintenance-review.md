# Candidate maintenance feasibility

Read-only primary GitHub API snapshots from October 7, 2026 are retained in
[the snapshot archive](evidence/maintenance-primary-snapshots.tar.gz). The [published manifest](evidence/maintenance-primary-manifest.json) records release metadata, source URLs and raw snapshot hashes. No
scan invoked a forge API and no version was adopted through this inspection.
Recent releases show maintenance activity, not an SLA or correctness guarantee.

| Candidate | Evaluated pin | Latest observed release | Recent activity in returned 12-release sample |
| --- | --- | --- | --- |
| Syft | 1.54.0 | 1.54.1, October 6 | 8 releases since July 16 |
| cdxgen | 13.3.0 | 13.3.0, October 2 | 11 releases since July 19 |
| SCALIBR | 0.5.3 | 0.5.3, September 22 | 3 releases since July 27; preceding release March 10 |

[Syft's pinned security policy](https://github.com/anchore/syft/blob/v1.54.0/SECURITY.md)
supports security fixes only in the newest release and uses best-effort security
intake. It distinguishes malicious inventory omissions from attacks against the
operator/system. SourceBastion therefore owns its coverage contract, input
containment and adversarial regression guarantees. Upstream package detection
alone does not establish complete inventory.

[Syft 1.54.1](https://github.com/anchore/syft/releases/tag/v1.54.1) includes a
deterministic .NET lock dependency fix and nine dependency updates. Evaluation
evidence stays pinned to 1.54.0. Before production adoption, S06 must assess this
upgrade, rerun affected source/corpus/native/resource checks and record exact
output changes. The .NET change directly illustrates why raw provider APIs and
canonical contracts need separate versions. No claim is made that 1.54.0 is the
currently supported newest release or that these release notes prove absence
of a security issue.

[cdxgen's pinned policy](https://github.com/cdxgen/cdxgen/blob/v13.3.0/SECURITY.md)
provides best-effort severity-based response targets, a security reporting
channel and security fixes for its last two releases/specification versions.
It assigns build-tool/network/environment responsibilities to users and does
not equate secure mode with forbidding all project tooling. That matches the
measured need for a separate hosted static boundary; policy text cannot repair
the evaluated execution/path/range failures.

[SCALIBR's public security policy](https://github.com/google/osv-scalibr/security/policy)
routes vulnerability intake to Google's process. Its pinned 0.5.3 source tree
does not contain a SECURITY.md, and a current repository-content lookup also
returns 404; the public policy page may use shared organization policy. Retain
that distinction instead of asserting an exact pinned policy file or a
contractual response guarantee. The release sample shows a longer release gap
than the other candidates; it does not prove abandonment.

SourceBastion scanner maintainers own adoption decisions and internal parsers.
Review upstream releases/advisories weekly and before each release; no recurring
automation has been created. Prioritize applicable security fixes immediately.
Every adoption needs pinned publisher/source/dependency identities and package,
edge, coverage, finding, native and resource/image differences against the
independent corpus. Security/support policy changes are review inputs, not
per-scan downloads. Exact update cadence, support matrix and operational
runbooks are S06 delivery obligations.

This is maintenance feasibility for the finite architecture decision. It is
not production distribution compliance, support procurement or engine acceptance.
