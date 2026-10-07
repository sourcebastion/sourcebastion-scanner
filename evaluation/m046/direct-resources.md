# Direct Python inventory/export resource candidate

Status: fourth S01 evaluation candidate; no architecture or engine selection.
The authoritative canonical Python frontend can emit a standard CycloneDX1.6
SBOM without first projecting its own records through the Go/Syft wrapper.
This experiment measures that route rather than assuming the wrapper is needed.
It does not replace required non-Python or installed-metadata adapters.

Two arms use the same prepared frontend and hash-pinned schema tool stack:
`direct-inventory` measures discovery/parsing plus bounded inventory serialization;
`direct-cyclonedx` includes that work plus export and offline schema validation.
Candidate execution imports only trusted code outside `/source`, under Python
`-I -B`. Preparation downloads verified wheels once and installs them into a
separate trusted tree before measurement. Wheel code/native-extension hashes are
compared with actual runtime maps; code/schema/requirements and tree hashes bind
the source and all attempts. No per-scan package or forge API is introduced.

The existing immutable Python3.14.8 Bookworm image and resource harness remain:
two CPU slots,2GiB cgroup charged memory/no swap,120 aggregate CPU seconds,150 wall
seconds,PID256,read-only source/host root,network none,UID/GID65534,64MiB raw file,
bounded tmp/work,heartbeat and PID-namespace cleanup. Charged memory is not RSS.
This generic comparison is not Alpine schema-stack packaging or image acceptance;
current schema wheel pins do not yet include musllinux rpds-py wheels.

Four independent pin fixtures (1k/10k/100k/100001;1/10/100/100roots) run three
times per arm/architecture,alternating arm order. A new container/tmp is used each
time; host page cache is not flushed. Attempts are checkpointed before launch;
infrastructure/source/cleanup uncertainty aborts the remaining plan. Expected
large refusals and invalid/OOM samples remain retained and separate from exact
results. The standalone audit runs under1GiB AS/20CPU/30wall/64MiB raw input and
compares independently generated exact package/root/source identities. Small and
medium fixtures must return complete exact output. Arbitrary failure reasons,
changed source, malformed or contradictory refusal data cannot pass as controlled
large refusal. Failure cannot prove packages absent.
Successful pairs must also have equal complete canonical inventories reconstructed
from the SBOM metadata/occurrence properties; package counts alone cannot prove
roundtrip fidelity. Uncomparable refusal/invalid pairs remain explicitly null.

100k is a structural ceiling, not guaranteed complete capacity. The independent
64MiB output and2M JSON node bounds can refuse earlier; all proposed bounds stay
visible and unchanged. Serialization refusal records its stage separately from
the source inventory status: it cannot claim that source parsing failed. The
100001 pipeline case may hit a byte/node bound first and therefore cannot prove
the count guard; semantic count-boundary contracts remain separate.
This benchmark does not define production persistence:
each job retains one measured output, and export refusal explicitly leaves
inventory retention unassessed. It never runs Grype. Full traversal/include/edge
stress, complete pipeline matching, native production image/licenses, non-Python
selection, reviewed budgets and development acceptance remain open.
