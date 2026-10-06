# M046 resource measurement foundation

This harness measures native candidate/container cgroup CPU and kernel-charged
peak memory on generated synthetic inputs. It is an evaluation tool, not an
engine, production sandbox, frozen budget, or milestone acceptance. Root/scope
graph fidelity and correctness are evaluated separately. Raw output is retained
unparsed; successful resource measurement does not mean a valid inventory.

Trusted setup pulls the immutable multi-architecture Python 3.14.8 bookworm image.
This full image is a benchmark baseline only; it is not a proposed production
runtime or evidence of the production image-size budget. Each job has a fresh
container/cgroup/tmp/cache, two native CPU slots, 2 GiB charged-memory limit, no
swap, 256 processes, 150 s wall and 120 aggregate CPU-seconds. The daemon is explicitly
local. Native ELF architecture, actual image architecture, full container identity,
unique PID cgroup, CPU quota, memory/swap/pids limits and effective cpuset are
verified before candidate execution. Unavailable or different limits fail closed.

The root controller retains only SETUID/SETGID/CHOWN/KILL capabilities. The candidate
runs as UID 65534 with no effective/permitted/inheritable capabilities and no-new-
privileges. Source/tool/harness mounts are read-only and networking is disabled.
Candidate working files use 256 MiB `/work` and 64 MiB `/tmp` tmpfs mounts. Retained
stdout/stderr and one raw result are each limited to 64 MiB. Controller paths are
private; markers have explicit permissions even under umask 000. Capture opens
directories/files without following links, refuses special/oversized/changing
files, and hashes the exact archived bytes. Permissions that prevent capture are
reported as failure, never bypassed.

The controller kills and drains every live candidate-UID task before capture.
Leftover descendants make a sample unusable even when the leader exits 0. Wall
measurement includes capture and the host's observation of completion; final
counters are sampled after completion. CPU/wall overruns, OOMs, cancellation,
capture uncertainty, source changes and missing raw bytes explicitly invalidate
resource samples. Driver SIGKILL stops work through the heartbeat watchdog;
the stopped Docker object remains for explicit inspection/removal. Normal driver
cleanup forcibly removes its exact named container, including escaped sessions.

## Reproduce

Use a disposable native Linux Docker evaluator, never an application DSN or a
customer repository. The existing development 8 CPU/12 GiB worker acceptance remains
separate. The controller image needs Docker with local cgroup peak/limit support.

```sh
rtk proxy python3 -c 'import platform; from evaluation.m046.benchmark import docker,IMAGE; docker("pull","--platform","linux/"+{"x86_64":"amd64","aarch64":"arm64"}[platform.machine()],IMAGE)'
rtk proxy python3 -m evaluation.m046.docker_proofs --output /absolute/new/proofs
rtk proxy python3 -m evaluation.m046.benchmark \
  --manifest /absolute/prepared/manifest.json --output /absolute/new/measurements \
  --fixture pins-1000-1-roots --fixture pins-10000-10-roots \
  --engine syft --engine cdxgen --engine scalibr --repeat 3
```

Proof programs are supervisor-owned synthetic code executed specifically to test
containment. Repository code is never an installation/execution fallback. Proof
execution under Python optimization is refused so acceptance assertions cannot
disappear. The eight probes cover marker/source/network boundaries under umask 000,
session escape, wall watchdog, raw symlink refusal, aggregate CPU cancellation,
kernel memory overflow, candidate tmpfs overflow and measuring-driver SIGKILL.
Native AMD64/ARM64 CI also measures all three stock candidates with three
repetitions of1k/10k/100k/100k+1 package occurrences across1/10/100 roots.
Engine/architecture pairs run in separate jobs with enough time for all12
bounded trials and selected-engine preparation. Each candidate has a separate bounded archive so package stress evidence does not
share the corpus archive ceiling. CI retains raw programs, controller records, tests and sources
in digest-indexed regular-file archives, including failed/incomplete jobs.

## Limits and remaining acceptance

Charged memory includes controller/file-cache charges and is **not aggregate RSS**;
shared pages charged elsewhere may differ. CPU includes the job controller/capture
after the start baseline; host fixture generation/snapshot/hash work is outside
the measured cgroup. The host's OS page cache is not flushed. Three repetitions
use fresh process/tmp/cache state, not proved cold host storage. Hosted/lab runs
may have contention and cannot establish dev capacity from these results.

The local review first reproduced and repaired output-path read/write escapes,
missing watchdog permission, descendant/counter timing, implicit marker modes,
native executable provenance and final budget classification. The initial five
real AMD64 probes and 66 focused tests were independently checked; later overflow,
optimization and full wall-accounting additions have separate exact-source proofs.
An unchanged pre-existing scaling timing test failed twice during full local runs
(50-file scan 55 ms, 100-file scan<1ms) and passed in isolation on the foundation base;
the failure records remain retained. The corrected test measures warmed actual
file traversal with CPU medians and verifies input counts; the final full
regression passed 1,271 with 97 skipped and two existing warnings.

Still required: reviewed extended-Syft/adapter comparison; untraced supported
small/medium/large/overflow graphs on both architectures; repeated performance
distributions and production image-layer deltas; aggregate-RSS evidence/explicit
reviewed measurement decision; frozen architecture/budgets; S02–S07 native tool,
frozen-advisory, platform/dev human ingestion and rollback acceptance. No current
sample closes those gates.
