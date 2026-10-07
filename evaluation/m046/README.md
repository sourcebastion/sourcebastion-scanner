# M046 S01 inventory evaluation

This first implementation is an executable **review candidate** for the oracle
and evaluator. It is not a production engine selection or milestone acceptance.
No production scan modules, image dependencies or runtime settings are changed.

The separate [static Python frontend prototype](static-prototype.md) explores
bounded general input discovery, typed include/constraint semantics and static
manifest declarations and typed Pipfile/pylock/Poetry/uv/PDM registry subsets. It is
under review, not an engine selection or a production integration.

`corpus.py` contains 64 handwritten cases with expected exact package identities,
evidenced edges, separate unresolved declarations and coverage dispositions. It
includes Python requirements/.in/custom hashed locks, hidden paths, includes and
constraints, markers/extras, conflicting roots, pyproject/setup/Pipfile/Poetry/uv/
pdm/pylock; npm/pnpm/yarn; Go modules; Cargo; and Java/.NET/Ruby/PHP regressions.
`oracle.py` adds hand-authored per-input dispositions/content hashes, root-aware
occurrences, source locators, scope/selection/marker/extras/compatibility evidence,
include/constraint references and separately reported fidelity axes. The exact
pip 26.0.1 build and hidden-lock regressions are included. Earlier incomplete lock
fragments are retained and labelled alongside structurally complete counterparts.
The v3 tranche labels the original minimal Pipfile metadata fragment partial and
adds a complete Pipfile positive. Prior 60-case v2 measurements remain bound to
their exact historical source/oracle, not this updated contract.
The v4 tranche adds three rich Python lock graph cases. Original Poetry bytes
with literal invalid content hash remain a malformed negative; minimal uv/PDM
locks retain known occurrences with explicit missing-source partial coverage.
Earlier v3 evidence remains bound to its 61-case source, not v4.
Unsafe paths reference only a synthetic sibling sentinel. Artifact integrity hashes
in synthetic locks are test strings, not verified package download hashes.

`run.py` materializes only these built-in inputs, verifies the supplied candidate
binary SHA256, invokes native tools in required Linux namespaces, retains raw JSON,
stdout/stderr/file/process/network traces, measures time/max-child RSS, compares
packages and edges, and records source snapshot equality. Stock exporters currently
have **unreported semantic dimensions**; they cannot earn full-contract agreement.
The substantive adapter must report and pass these dimensions before selection;
empty output and exit 0 never prove them.
Cross-run package/edge equality is assessed independently from SBOM timestamps,
UUIDs, paths and other unstable fields.

The `syft-projection` variant is a bounded experiment: content-validated exact-pin
`.in`/`.txt` files are copied into conventional filenames in the synthetic fixture
before its read-only mount. Original bytes remain intact and the projection map
is retained. It refuses includes, ranges, markers and prose. It is not the general
discovery/graph adapter proposed by M046 and must not be shipped as one.

## Reproduce on an isolated Linux evaluator host

The host needs Python 3.11+, `unshare`, `mount`, strace and enabled user namespaces.
Downloads/builds happen before offline scans. No forge credentials are needed in
the scan environment. Use the pinned assets/source in `tools.json`; the evaluator
checks the **extracted binary** digest, distinct from the archive digest.

```sh
rtk proxy python3 evaluation/m046/run.py \
  --engine syft --binary /path/to/syft \
  --sha256 d46a9a61a6ae3d367f0a03748c5e9c59253e586c4388ab26ddcacebc2efa0d92 \
  --strace /path/to/strace --output /absolute/new/output/path --repeat 2
```

Repeat for `syft-projection`, `cdxgen` and `scalibr` using their binary digests.
For cdxgen, first unpack its verified standalone asset with `--version` outside
the scan. Invoke its prepared `node_modules/.bin/node-real` as `--binary` and
`bin/cdxgen.js` as `--entrypoint`, with `--entrypoint-sha256` and
`--entrypoint-tree-sha256` from `tools.json`. The tree digest includes its complete
bundled module snapshot and permissions; differing extraction permissions require
review of the retained manifest rather than bypassing the check. This separates
tool installation from extraction: the 108 MiB Node executable cannot be unpacked
under the evaluator's 64 MiB per-file output ceiling. Scan timing excludes unpacking.
`--fixture ID` can be repeated for a targeted probe. Output must not exist; evidence
is never overwritten. Run candidates sequentially. Scans are offline, but building
SCALIBR needs its pinned Go modules downloaded first. The pinned source built with
Go 1.27.1 needs `-tags=http2legacy` for its gRPC/x/net compatibility; record this
build flag and do not modify its go.mod or silently update dependencies.

```sh
rtk proxy env GOCACHE=/task/cache GOPATH=/task/modules GOTOOLCHAIN=local \
  /path/to/go/bin/go build -p 2 -tags=http2legacy -trimpath \
  -o /path/to/scalibr ./binary/scalibr
rtk proxy env M046_STRACE=/path/to/strace python3 -m pytest tests/test_m046_inventory_eval.py
```

Unit tests run without downloading tools. Opt-in native tests prove denied
network/source writes, environment scrubbing, deadline termination, evaluator
SIGTERM/SIGKILL cleanup, inherited blocked signals and parent-registration races. Synthetic
oracle review and engine safety review remain independent gates.

## Native CI and deterministic stress inputs

`.github/workflows/m046-evaluation.yml` builds and evaluates the pinned candidates
on native AMD64 and ARM64 runners. `prepare.py` permits network only during trusted
asset/source/module preparation; `native.py` runs every candidate sequentially in
the offline synthetic evaluator. Derived binary/runtime/module-tree identities and
raw evidence are retained for seven days. An infrastructure error fails the job;
no online fallback or emulated native acceptance is permitted.
The archive contains regular files only. Synthetic cyclic/escaping links are
stored in `SYMLINKS.json` as data, so artifact upload never follows them. Each
member is digest-indexed; the archive and its digest are uploaded together. The
combined evaluation archive has a separate 1 GiB raw-file ceiling; this does not
claim enforcement of the proposed 256 MiB production job diagnostic ceiling.

`performance_corpus.py` generates package, traversal, include-depth/fanout/cycle,
file-size and graph boundary inputs. Each source has an independent sidecar oracle
with counts and identity/occurrence/root-aware-edge digests. The sidecar is never
inside scanned sources. These generators are prepared for untraced cgroup tests;
their existence does not establish performance acceptance or freeze any budget.

```sh
rtk proxy python3 -m evaluation.m046.performance_corpus \
  --output /absolute/new/performance/path --fixture pins-1000-1-roots
```

The committed initial 50-case raw archive and `measurements.json` describe corpus
v1 and its captured runner. They are historical diagnostic evidence, not current
v2 comparison/acceptance. Never mix reports from different corpus/oracle digests.

`benchmark.py` and `container_job.py` provide a separate untraced Docker/cgroup
measurement harness, with real native capability, watchdog, output-boundary and
overflow probes in `docker_proofs.py`. See [performance.md](performance.md) for
reproduction, exact measurement scope and remaining acceptance. Native CI runs
these proofs on both architectures and retains the benchmark tests with sources.

## Safety and evidence limitations

Use this only on the built-in synthetic corpus. Namespace isolation does not hide
the host filesystem/Unix sockets and is not a production jail. Noexec does not
block interpreter reads. Inspect all child executions and source/write/network
operations. `source_unchanged` records retained bytes/links/directories, not every
attempted write. The 45-second evaluation timeout differs from the proposed
production ceiling. Traced timing is diagnostic; max-child RSS is not aggregate
memory. See [contract.md](contract.md) for the proposed contract/budgets and missing
performance/native acceptance. See [comparison.md](comparison.md) for measured
results and the architecture decision's current status.

## Substantive Syft candidate

The actual custom-cataloger and same-library CPE control prototype is described
in [extended-syft.md](extended-syft.md). It retains rich Python inventory with
occurrence IDs and explicit graph/export losses. Evaluation only; no engine
selection, resource acceptance or production integration.
