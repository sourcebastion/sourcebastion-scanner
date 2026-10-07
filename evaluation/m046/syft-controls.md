# Same-library CPE resource controls

This evaluation compares Syft 1.54.0 library CPE generation on and off using
the same source-bound binary and explicit offline cataloger configuration from
the extended-Syft experiment. It tests one possible contributor to the earlier
stock CLI memory failures. It does not assume the library profile is identical
to the stock CLI or prove that CPEs caused its failures.

Both arms use the existing native resource harness without changing its
controller, file bounds, UID isolation, cgroup enforcement, watchdog or cleanup.
A trusted Python launcher runs under candidate UID 65534, exclusively creates
`/work/raw.json`, redirects stdout there and execs the pinned Go binary. The file
explicitly permits controller reads (0644), including under a restrictive umask;
the root controller keeps its existing lack of DAC_OVERRIDE capability. The
launcher reads no project code and performs no installation. It and the native Go process
share the measured cgroup, as does the root job controller. Trusted build/source
generation and the bounded post-measurement correctness audit remain outside it.

The immutable Python 3.14.8 bookworm image is the existing full benchmark image.
The control mode does not invoke the Python dependency frontend, so this does
not prove the combined extension's Python runtime, memory or output behavior.
In particular the extension's possible 128 MiB + 4096-byte wrapper cannot be
measured by this unchanged 64 MiB raw-result controller.

Each native AMD64/ARM64 comparison measures 1,000, 10,000, 100,000 and 100,001
synthetic pinned dependencies across 1/10/100 roots, with three repetitions of
both arms (24 attempts per architecture). CPE arm order alternates by repetition.
Each attempt uses a fresh container/tmp/cache, two CPU slots, 2 GiB kernel-charged
memory, 120 aggregate CPU seconds, 150 seconds wall, no swap, disabled networking
and read-only source/tool/harness mounts. Host OS page cache is not flushed;
source generation and earlier arms may warm shared pages. Charged memory includes
controller/file-cache charges and is not aggregate RSS. Budgets remain proposed.

All attempted runs, including OOM, deadline, serialization/output-limit and
capture failures, retain their measurements and diagnostics. Exit 0 or empty
output alone never counts as a valid inventory. A separate isolated Python
process is bounded to 1 GiB address space, 20 CPU seconds, 30 seconds wall and
64 MiB input. It checks unique artifact IDs, package purls, exact independent
identity hashes and original root-aware occurrences. It then strips only CPEs
and the tool descriptor, normalizes array order and hashes the entire remaining
document. A timing comparison requires successful exact audits for both arms
and equal non-CPE hashes; uncomparable pairs are reported as null. Small/medium
gate failures fail the workflow after retaining all attempts. Large failures
are measurements to review, never successful throughput samples.

Returning 100,001 packages in a stock control does not enforce the frontend's
proposed 100,000-occurrence ceiling. Pins do not characterize include traversal,
lock parsing, graph growth or environment semantics. Actual production image
growth, licenses, matching compatibility, full extension resources and dev worker
acceptance remain separate gates before engine selection.

Reproduce only in a disposable native Linux Docker evaluator:

```sh
rtk proxy python3 -m evaluation.m046.syft_prepare --output /absolute/new/preparation
rtk proxy python3 -m evaluation.m046.syft_control_benchmark \
  --binary /absolute/new/preparation/m046-syft \
  --manifest /absolute/new/preparation/manifest.json \
  --output /absolute/new/comparison --repeat 3
```

The workflow first reruns the existing eight real Docker harness probes on both
architectures and three new native C stand-in probes through the actual launcher
mount/command path. Both toggles must retain the exact argv and UID/GID 65534;
the overflow probe must refuse success while retaining at most 64 MiB. Stand-in
code is trusted harness material, never a project execution fallback. Every
measurement attempt is checkpointed before execution and after capture/audit.
Infrastructure, source or cleanup uncertainty aborts further attempts and records
planned, started, completed and not-started counts. The affected pair cannot
remain eligible when its final source/binary identity check fails.
Raw archives keep their 64 MiB per-file/1 GiB total bounds. The
larger compiled binary uploads separately; audit its native ELF/hash/size against
the preparation manifest and verify all archived source/inner hashes. Successful
CI is evidence collection, not independent acceptance or milestone closure.
