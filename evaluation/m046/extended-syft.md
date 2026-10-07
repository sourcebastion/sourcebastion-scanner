# Extended Syft evaluation

Status: controlled prototype; no engine choice, resource/budget acceptance,
S01 completion or production integration. This is the substantive cataloger
candidate following the intentionally narrow filename projection in `run.py`.

`syft_extension` pins the Syft 1.54.0 Go library and its complete module graph.
Trusted preparation downloads the checksummed Go 1.27.1 toolchain, verifies
modules, tests and builds the candidate. Preparation can use the network;
candidate execution cannot install or download dependencies. Python 3.14.8,
packaging 25.0 and Poetry Core 2.1.3 retain their separate runtime/source pins.
Preparation captures the complete Go module, frontend/evaluator sources, corpus
and tool-pin hashes before the build and checks them after every command. Native
evaluation requires that manifest to match both the executable hash and current
candidate sources; freshly hashing an unrelated binary is insufficient.
Raw/source evidence retains the existing archive's 64 MiB per-file bound. The
larger compiled executable uploads separately and must match the preparation
manifest and native summary hashes before an artifact audit can accept it.

## Two separate experiments

`--mode control --generate-cpes=true|false` compares the same library binary and
explicit cataloger configuration. The only changed effective cataloging value
is generated CPE enrichment; tool metadata records the toggle. Existing
authoritative CPEs can remain. This profile disables Go packages execution,
remote/local license enrichment, Maven network/local repository/transitive
resolution and Vcpkg cloning. JavaScript development dependencies are included.
Missing stock versions remain missing rather than being invented as UNKNOWN.
This is a library profile, not asserted parity with the stock Syft CLI.

`--mode extended` adds an actual `pkg.Cataloger` which invokes the reviewed
bounded Python frontend exactly once under the shared job context. The stock
Python declaration cataloger is removed; the installed Python package cataloger
is explicitly retained. Other default directory catalogers retain their own
semantic limitations. The frontend v5 registry explicitly refuses uv script
locks (`*.py.lock`) and installed egg/dist metadata instead of ignoring them.
The latter remains separately available through the retained stock cataloger.
Script-lock/project association and richer installed metadata fidelity are open.

## Occurrences, graphs and losses

Only selected Python occurrences become custom Syft packages. Unselected ranges,
constraints alone and first-party application records stay in the rich inventory.
The purl/name/version remain ecosystem identity; root, scope, extras and markers
are not encoded as invented package qualifiers. Domain-separated SHA256 IDs bind
the complete canonical typed occurrence and contract version. Location annotations
carry the occurrence key and original locator. Equal purls at distinct locators
remain distinct artifacts, including PDM extras-to-base edges.

The complete typed inventory is retained in the sidecar. Package fields, location
annotations and relation endpoints/data have immutable pre-finalization signatures;
any lost or altered custom result refuses the combined output. Standard SyftJSON
roundtrip is checked separately. There is no fabricated custom metadata type:
Syft's internal metadata registry would not preserve it through a decoder.

Rich dependency edges are parent-to-child; Syft relation endpoints reverse that
direction. `m046-informational-dependency` deliberately preserves informational
evidence without asserting installed/active dependency reachability. Ambiguous
group/marker endpoint mappings remain in the rich sidecar with explicit unmapped
indices and reasons. Standard CycloneDX/SPDX export and Grype discard these custom
relations; the sidecar lists these projection losses. A standard export alone
cannot claim the rich graph, environment or activation contract.

Extended stdout is a versioned **evaluation bundle**, containing the SyftJSON
document and sidecar, not a standard SBOM. Whole-repository coverage stays unknown;
Python frontend coverage and retained stock coverage are not silently combined
into complete. Matching remains not-run. A matching controller must explicitly
extract the SyftJSON document and retain the sidecar/ID index.

## Admission and boundaries

Frontend JSON rejects duplicate keys, trailing documents, excessive nesting/token
counts, missing dimensions, malformed selected identities/provenance/context,
invalid fidelity enums and contradictory coverage. Package/edge/application
summaries must agree with the rich records. The adapter's version grammar is the
PEP 440 lexical pattern from pinned packaging 25.0; it does not resolve or compare
versions. Python's maintained parser remains the semantic source.

Frontend stdout is bounded to 64 MiB, stderr to 64 KiB, each inventory sidecar and
Syft serialization to 64 MiB, and the wrapper to their combined ceiling. The Go
buffer exposes no promoted unbounded `ReadFrom`/`WriteString` methods. Real pipe
overflow/cancellation tests supplement direct writer tests. Projection uses a
name/root/path index, at most 100,000 occurrences/edges and five million candidate
checks. All stages share the outer context deadline (maximum 150 seconds).

The source must be the same immutable, read-only snapshot for both readers.
Controller code/interpreter/module paths are trusted and outside that snapshot.
Resolving the Python path for trust checks must not replace a trusted venv path
with its base interpreter at execution. No shell or project command is invoked.
The outer job boundary must enforce process-tree cleanup, memory/CPU/diagnostic
budgets, blocked sockets/host reads and source immutability. Writer limits do not
bound Syft model creation, decoder allocations or retained stock catalogers.

`syft_native.py` uses the existing required network/user/mount/PID namespaces,
read-only/noexec source mount, two CPU affinity slots and whole-group guardian.
It binds Python/Go source/tool hashes, retains 64 raw fixture results and compares
40 admitted rich contracts. Four stock library CPE pairs check all non-CPE data
for equality. Traces allow Go runtime threads and the one trusted Python process;
unexpected process or socket attempts fail even if denied. The trace scope
process/network/%file does not cover descriptor-only write families. The existing
host-read-visible harness is a diagnostic environment, not a production jail.
Pinned Go 1.27.1 can create one additional pidfd capability-probe child before
Python starts. Admission requires exact probe clone flags, a known Go parent,
successful creation, captured child calls limited to `exit_group(0)`, and matching
successful `__WCLONE` reap. The summary reports it separately. This classification
uses the captured trace plus pinned runtime source; the trace omits other syscall
families and does not prove universal absence of child reads/writes.
The verifier independently recomputes occurrence IDs/purls and graph endpoint
provenance, including unmapped-edge decisions, rather than accepting agreement
between the adapter's own projection claims and its exported document.

## Acceptance still required

Native current-head artifacts require independent audit. Local Python 3.13 runs
are diagnostic only. Stock/extended CPE controls need new full-candidate native
cgroup resource evidence, overflow/cancellation proofs and measured image/license
costs before budgets are reviewed and frozen.

The separate [same-library CPE resource controls](syft-controls.md) preserve the
existing 64 MiB raw-result harness. They characterize the library control profile
first; they do not establish full extension resources or its larger wrapper bound.

Actual pinned Grype 0.119.0 embeds older Syft 1.52.0: producer-only decoding is
insufficient. Use explicit SBOM input and a frozen verified offline database,
disable Grype CPE regeneration for CPE-off comparisons, record per-matcher CPE
settings, and verify occurrence IDs/purls/locations plus contextual match fanout.
Python CVE agreement alone cannot establish safety for CPE-dependent ecosystems.
CycloneDX schema/reference validation, translated occurrence identity and precise
loss accounting remain separate. No comparison authorizes engine selection,
production release, deployment, customer replay or milestone closure.

Primary sources: pinned [Syft cataloger API](https://github.com/anchore/syft/blob/v1.54.0/syft/pkg/cataloger.go),
[custom catalogers](https://github.com/anchore/syft/blob/v1.54.0/syft/create_sbom_config.go),
[CPE enrichment](https://github.com/anchore/syft/blob/v1.54.0/syft/cataloging/data_generation.go),
[package identity](https://github.com/anchore/syft/blob/v1.54.0/syft/pkg/package.go),
[Python catalogers](https://github.com/anchore/syft/blob/v1.54.0/syft/pkg/cataloger/python/cataloger.go),
[Grype conversion](https://github.com/anchore/grype/blob/v0.119.0/grype/pkg/package.go),
[Grype dependency pins](https://github.com/anchore/grype/blob/v0.119.0/go.mod).
