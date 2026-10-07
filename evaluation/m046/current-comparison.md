# Current S01 evidence comparison

2026-10-07. Architecture decision and numerical freeze remain pending.
This supersedes the initial 50-case summary for current decision-making;
historical raw evidence and limitations remain unchanged.

## Retained common input subset

The pinned stock Syft 1.54.0, cdxgen 13.3.0, SCALIBR 0.5.3 and exact-pin projection
profiles each retain two AMD64 attempts for 60 identical original cases. Their
raw outputs are re-compared against the current 64-case independent oracle.
Four later cases remain not evaluated for those profiles. This is not new tool
execution, native ARM64 acceptance or a fresh 64-case benchmark.

Exact input trees, imported comparison code, raw/trace hashes and projection
origin/transformation maps were checked. The projection intentionally strips
hash options and copies only admitted exact pins into conventional filenames;
its transformed input is explicitly different from stock input. All historical
trace admission remains `manual-review-required`.

| Profile | Retained cases | Not evaluated | Exact packages/edges | Also exact applications | Rich full contract |
| --- | ---: | ---: | ---: | ---: | ---: |
| Stock Syft | 60 | 4 | 38 | 37 | 0 |
| cdxgen, offline flags | 60 | 4 | 32 | 9 | 0 |
| SCALIBR, offline plugins | 60 | 4 | 38 | 38 | 0 |
| Narrow exact-pin projection | 60 | 4 | 43 | 42 | 0 |

Agreements include empty negative cases and are not accuracy percentages or
coverage acceptance. The corrected Poetry fragment oracle requires missing
metadata to remain unsupported; that lowers each historical basic total by one.
Source inputs themselves are unchanged. Every rich axis stays unreported for
these stock/exporter profiles, even when the identity sets agree.

The retained/current-oracle report SHA256 is
`9a408fc1d168c0c799915b965fe0aad57856eb0fb3b969a7474e859dcc2f649f`.
Its private raw archive is diagnostic evidence, not a production input dependency.

## Additional source-bound evidence

| Candidate part | Observed capability | Limits remaining |
| --- | --- | --- |
| Direct canonical Python | 40 reviewed rich Python contracts; static declarations/includes/constraints/manifests/locks, roots and conditions; native runtime proofs | Non-Python/installed canonical adapters unimplemented; prototype not production registry |
| Substantive Syft extension | Invokes the same trusted Python frontend once; retains authoritative sidecar and raw Syft projection; native static Alpine overlay works | Conversion cost and projection losses; historical complete-capture failures remain refused; no demonstrated need for this extra conversion in the preferred route |
| Restricted Syft provider | Current PR107 head `4774e19`, 130 attempts/architecture, 65 equal repeat/cross-architecture fact sets; all 260 strict traces admitted in this run | Basic 32/65 includes empty cases/application omissions; rich dimensions unreported, canonical adapters still required |
| Composition feasibility | Distinct authorities/roots; source-bound installed/application metadata; unselected versionless/declaration evidence; contextual raw-ID edges | Small incomplete prototype; overall partial; no canonical non-Python matching edges/export/cache |

The restricted-provider
[native run](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/37585277647)
has independently checked API/ZIP digests, 1,106 inner hashes and 84 exact source
files per architecture. Independent report SHA256
`1ba5c7424cbced14d87f04e1ea0878e087fab5b42c27b08f16617df16eca0c98`.
Historical `???` captures remain refused. A successful finite observation is not
a universal isolation proof or qualification of unmeasured semantic axes.

## Safety, resources, packaging and maintenance

cdxgen's evaluated no-install profile still attempts Go project tooling and
follows the synthetic outside-root symlink; a tested Python range becomes its
floor version. It is ineligible for the current hosted static profile without a
specific corrected boundary. SCALIBR is fast in synthetic pins, but its exporter
omits tested edges and changes module/root representations. Neither finding
justifies building an equivalent complete production adapter for every rival.

Direct inventory/CDX cgroup trials are independently measured on both native
architectures: complete through 10k flat pins; 100k inventory completes but CDX
refuses its 2M-node bound; 100001 inputs retain explicit partial/budget status.
The 100k structural maximum is not a complete SBOM capacity promise. CPE-off
library controls improve small/medium cost; they do not repair the extension's
large-output or historical trace failures. Proposed ceilings remain 2 CPU,
2 GiB kernel-charged memory, zero swap, 120 aggregate CPU seconds, 150 wall
seconds clamped by the global deadline, 256 PIDs and 64 MiB per inventory/SBOM.
They need a concrete numerical review/freeze, not an RSS relabelling.

All three candidate projects declare Apache-2.0. Direct Python dependencies
include MIT, Apache/BSD and Rust dual-license categories. Verified publisher
identity is separate from distribution compliance. Both candidate musl rpds
wheels bundle `libgcc_s.so.1`; native loaded closure, origins and redistribution
notices remain specific S06 obligations. Actual native Alpine import/export
feasibility for the seven-wheel direct schema stack remains an S01 check if
Alpine is the selected mandatory runtime. The existing Go/Alpine overlay does
not establish that capability. No incompatible license has been established;
complete release compliance is not claimed.

Proposed implementation/update owner: SourceBastion scanner maintainers.
Require pinned tool/parser/schema/registry versions and provenance per upgrade;
rerun independent corpus, static behavior, native architectures and affected
resource/image checks before adoption. Provider APIs and canonical contracts
must version independently. Keep update preparation separate from offline scan
execution; normal scans require neither forge APIs nor dependency installation.
Maintenance cadence, support matrix and final release runbook remain S06 work.

## Finite architecture exit

Review the current matrix and [composition contract](composition-contract.md),
the small mixed execution, native selected-runtime/image feasibility, numerical
ceilings and license feasibility. Then accept or reject the architecture itself.
Complete S02-S07 implementation and release/dev acceptance remain mandatory
afterward. A new optional seccomp experiment is not silently added as an S01
prerequisite. Pivot once only for a named unmet requirement such as required
source execution/network access, unavailable identity/context, incompatible
license, mandatory runtime failure or measured budget infeasibility.
