# Preliminary S01 comparison and decision record

Date: 2026-10-06. Status: evaluation started; **engine decision deferred**.
This is the first evidence tranche for scanner #89/#88, not S01 acceptance.
The corpus/oracle has not received independent approval. Exact package/edge
agreement is not vulnerability accuracy or coverage completeness.

## Method and reproducibility

Pinned native AMD64 candidates: Syft 1.54.0, cdxgen 13.3.0, OSV-SCALIBR 0.5.3,
plus the narrowly scoped Syft exact-pin projection probe. Expectations were
handwritten from manifest semantics, not derived from candidate output. See
`tools.json`, `corpus.py`, `measurements.json`, `table.md` and retained raw evidence.
All candidates ran sequentially on the same Linux host with two affinity slots,
disabled network, read-only synthetic input, environment scrubbing, strace and a
45-second per-run deadline. These are small correctness probes; timing and
maximum-child RSS are diagnostic and do not establish production budgets.

Syft and SCALIBR have two runs per input; cdxgen and the projection probe have one.
The initial Syft run predates the runner's full argument tracing and runner-digest
field. Its corpus digest and raw commands/outputs/traces are retained. Later runs
use 4,096-character trace strings and record runner SHA256. No corpus inputs or
expectations changed between candidates. This method difference limits trace
comparisons; it does not justify claiming current-head benchmark acceptance.
The evidence archive includes the measured runner/corpus before source formatting;
the formatted corpus was checked for exact input/expectation equality.

| Configuration | Runs | Exact package/edge agreements (of 50) | Median traced wall | Max child RSS |
|---|---:|---:|---:|---:|
| Syft | 100 | 39 | 3.317 s | 193.0 MiB |
| cdxgen, prepared runtime | 50 | 30 | 5.152 s | 161.4 MiB |
| SCALIBR | 100 | 36 | 0.353 s | 47.7 MiB |
| Syft exact-pin projection | 50 | 42 | 3.267 s | 192.6 MiB |

These counts include cases expecting no exact packages; they are **not accuracy
percentages**. All candidates retained the original source snapshots. Syft and
SCALIBR produced identical normalized inventory on their valid paired runs. The
invalid/nonzero SCALIBR malformed-input runs are excluded from repeat equality.

Candidate commands are the explicit configurations in the raw reports. Syft
includes Node development dependencies. cdxgen disables installs, Babel analysis,
cache, introspection and Rust acceleration, targeting CycloneDX 1.6. SCALIBR uses
offline filesystem language plugins with unsafe plugins disabled, and its
CycloneDX exporter. No credentialed forge calls or production paths are used.

cdxgen's first bundled-launcher attempt failed while unpacking its 108 MiB Node
runtime under a 64 MiB per-file output ceiling. That setup attempt is excluded
from inventory comparisons. Its verified release was unpacked first; the Node
runtime, JS entrypoint and complete prepared application tree were pinned, then
extraction ran under the unchanged ceiling. The prepared tree remained unchanged.
SCALIBR's pinned modules built with Go 1.27.1 and `-tags=http2legacy`; the untagged
build failed at gRPC's use of x/net/http2.TrailerPrefix. No modules were updated.

## Findings from the initial candidate configurations

- Stock Syft misses `.in` and custom hashed `.txt` locks, pyproject declarations,
  setup.cfg, pylock variants and the custom include target. It inventories the
  conventional lock formats tested and preserves the two evidenced npm/Cargo
  edges in its native JSON. Its Pipfile output omits the tested development group.
- The Syft projection is an experiment, not the proposed general solution. It
  copies complete exact-pin-only content into a conventional filename and retains
  an origin map. Entire inputs containing include/constraint directives are
  refused, so constraints cannot become independently installed packages. It does
  not solve markers, unresolved versions, root reachability or parser coverage.
- cdxgen in this offline configuration has discovery/declaration omissions too.
  For `requests>=2.31,<3`, its output purl selects `2.31`. The oracle expects a
  range-only declaration, so this remains an extra package, not accepted version
  evidence. Its Go path attempts `go list` and `go mod graph` despite
  `--no-install-deps`; those executables are absent from the scrubbed PATH. A
  no-install flag therefore does not establish a static, bounded metadata policy.
  It also follows the `requirements.txt` symlink outside the scan root and emits
  `m046-outside-sentinel@99.99.99`. That is controlled synthetic test data; the
  observed escape is a boundary failure to address before hosted qualification.
- SCALIBR follows the tested requirements include and includes both tested
  Pipfile groups; it still misses custom filenames and the tested pyproject
  dependency declarations. Its CycloneDX output contains first-party roots and
  Go stdlib declarations, strips the module-version `v` prefix, and lacks the two
  tested package edges. These are explicit inventory/exporter/normalization
  differences, not proof of vulnerability misses. A library adapter needs further
  characterization before deciding whether those differences are acceptable.

Empty output for malformed, dynamic or unsafe input does not satisfy the expected
coverage disposition. Coverage/declaration comparison stays `unassessed` for every
engine until a reviewed adapter exposes those outcomes. Negative exact-identity
agreement cannot be reported as a successful safety/coverage test. The evaluator
also deliberately does not filter first-party/stdlib extras against the oracle.
SCALIBR's nonzero exit for malformed package-lock JSON is an explicit rejection;
the table's execution/output-error label is not a claim that rejecting malformed
input is wrong. The coverage adapter must preserve that rejection's meaning.

Raw execution, network and file traces need independent review. `getent` and
`ldd --version` observations are environment probes; namespace denial and source
snapshot equality do not establish that arbitrary source code can never execute.
The evaluator does not hide host filesystem/Unix sockets and cannot qualify as a
production isolation boundary. The unsafe fixtures use only a synthetic sibling
sentinel, never real outside data.

## License, maintenance and packaging review

All three projects' pinned top-level licenses are Apache-2.0:
[Syft](https://github.com/anchore/syft/blob/v1.54.0/LICENSE),
[cdxgen](https://github.com/cdxgen/cdxgen/blob/v13.3.0/LICENSE),
[SCALIBR](https://github.com/google/osv-scalibr/blob/v0.5.3/LICENSE).
This establishes the project's stated license; bundled/transitive dependency
licenses, attribution obligations and hosted distribution still need a packaging
review. No candidate is added to the production image by this PR.

Pinned release dates are Syft 2026-10-01, cdxgen 2026-10-02 and SCALIBR 2026-09-22.
They demonstrate recent releases, not a maintenance SLA. Review release cadence,
security handling, parser update tests and upgrade ownership before selection.
Syft/cdxgen publish Linux AMD64/ARM64 assets. SCALIBR provides source; the evaluated
AMD64 binary is 69,608,556 bytes. cdxgen's AMD64 standalone is 175,887,723 bytes;
Syft's AMD64 archive is 29,217,540 bytes. Binary/archive sizes cannot substitute
for measured scanner image layer deltas or native ARM64 execution.

## Decision and next tranche

No evaluated configuration satisfies the full local discovery/graph/coverage
contract as-is. Keep the candidate set open. Build and review the registry and
graph contract around demonstrated gaps, then evaluate a substantive Syft
cataloger extension and targeted SCALIBR/cdxgen adapters. ORT or CycloneDX Python
should be added only if their offline adapters improve measured coverage without
source execution. Do not replace the current engine using the agreement totals.

Before accepting S01: independently review at least 40 oracle cases and detailed
per-input dispositions; add realistic complete generated locks and full target
environment/root semantics; publish stress and aggregate resource/image evidence
on native AMD64/ARM64; repeat all selected configurations under the final runner;
review engine policy/traces and licenses; approve the architecture decision and
freeze numerical budgets from [contract.md](contract.md). Production implementation,
Grype matching/cache compatibility, platform coverage and dev acceptance follow
the subsequent slices. M047 owns the SBOM browser UI.
