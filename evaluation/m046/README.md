# M046 S01 inventory evaluation

This first implementation is an executable **review candidate** for the oracle
and evaluator. It is not a production engine selection or milestone acceptance.
No production scan modules, image dependencies or runtime settings are changed.

`corpus.py` contains 50 handwritten cases with expected exact package identities,
evidenced edges, separate unresolved declarations and coverage dispositions. It
includes Python requirements/.in/custom hashed locks, hidden paths, includes and
constraints, markers/extras, conflicting roots, pyproject/setup/Pipfile/Poetry/uv/
pdm/pylock; npm/pnpm/yarn; Go modules; Cargo; and Java/.NET/Ruby/PHP regressions.
Unsafe paths reference only a synthetic sibling sentinel. Artifact integrity hashes
in synthetic locks are test strings, not verified package download hashes.

`run.py` materializes only these built-in inputs, verifies the supplied candidate
binary SHA256, invokes native tools in required Linux namespaces, retains raw JSON,
stdout/stderr/file/process/network traces, measures time/max-child RSS, compares
packages and edges, and records source snapshot equality. Coverage and declarations
remain **unassessed** in comparisons; empty output and exit 0 never prove them.
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

Unit tests run without downloading tools. Two opt-in native tests prove denied
network/source writes, environment scrubbing and deadline termination. Synthetic
oracle review and engine safety review remain independent gates.

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
