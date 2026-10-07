# S01 reviewed evidence

This documentation PR records the architecture decision independently of the
experimental implementation stack. It changes no scanner route or dependency.
All experiments remain separately reviewable at their exact source heads.
Historical failures are retained; a successful audit does not make all checks
green or establish production acceptance.

| Evidence | Frozen source / native run | Retained audit |
| --- | --- | --- |
| Direct Python semantics, 64 cases / 40 rich contracts | [#100](https://github.com/sourcebastion/sourcebastion-scanner/pull/100), `276b2863322afc9c2b792f8b755c7b9d6e85897d` | See source PR for exact workflow evidence |
| Actual extended Syft frontend | [#101](https://github.com/sourcebastion/sourcebastion-scanner/pull/101), `7e1d04434ab2340e46e2058026c43723c4e1f816` | [run37564740814](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/37564740814); historical undecoded traces remain refused |
| Provider CPE/resource controls | [#102](https://github.com/sourcebastion/sourcebastion-scanner/pull/102), `3ea43d9e85c508e421c9261af78b4b3edbe46c83` | [run37570179837](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/37570179837) |
| Static Go overlay / release baseline | [#103](https://github.com/sourcebastion/sourcebastion-scanner/pull/103), `e818611a2e8e4263b57530c519c9e48419c6f8cb` | [run37572007576](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/37572007576) |
| CycloneDX contract | [#104](https://github.com/sourcebastion/sourcebastion-scanner/pull/104), `2d578b224afb77d367b3878756f3a728e54860a6` | [run37574897391](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/37574897391) |
| Direct inventory/export resource envelope | [#106](https://github.com/sourcebastion/sourcebastion-scanner/pull/106), `d7b6f603a25d7ee471602688c78cbb01f3859773` | [run37577576880](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/37577576880) |
| Minimal mixed provider/source composition | [#108](https://github.com/sourcebastion/sourcebastion-scanner/pull/108), `612e39cb320911184f19855ae903164d46d0c8e2` | [run37588602868](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/37588602868), [independent verification](composition-independent-verification.json) |
| Seven-wheel actual Alpine import/export | [#109](https://github.com/sourcebastion/sourcebastion-scanner/pull/109), `d98fbd0fb9c5563999a5c061a12fb68191fddd86` | [run37590730428](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/37590730428), [independent verification](direct-alpine-independent-verification.json) |

The [retained 60-case comparison](retained-common-60.md) includes raw candidate
outputs, traces, unchanged inputs, transformed-input provenance, the executable
64-case independent corpus/oracle, tool pins and a replay script. Its current
480-record replay is [independently verified](portable-comparison-independent-verification.json).
Four later corpus cases were not measured for the stock profiles. Historical
trace admission remains manual-review-required, and the rich contract is not
met by any stock exporter. This is not a vulnerability accuracy percentage.

The [independent design review](S01-independent-review.md) recommends S01
acceptance with no remaining design blocker after durable publication. Its
pre-publication decision/maintenance hashes differ from these documents only
because publication updates status, verified runtime facts and links.
The dated [maintenance review](../maintenance-review.md) has a
[raw primary snapshot archive](maintenance-primary-snapshots.tar.gz) and
[manifest](maintenance-primary-manifest.json). No per-scan forge API is used.

`SHA256SUMS` binds every regular file in this evidence directory except itself.
The comparison archive also has its own inner checksums and adjacent outer
checksum. GitHub native workflow artifacts have finite retention; source heads
and rerunnable workflows remain in the linked candidate PRs. This publication
retains stock raw data and bounded independent native audit reports, not the
large OCI images or every native raw artifact. Re-run a workflow if raw artifact
retention expires; do not infer fresh evidence from a historical audit.

No experiment is production engine acceptance. S02–S07 retain production
registry/adapters, real native Grype compatibility, platform integration,
complete pipeline budgets/isolation, bundled libgcc distribution obligations,
release provenance and development human/rollback acceptance.
