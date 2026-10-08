# Inactive streaming capture primitive

`ArtifactStore.writer` reserves the entire configured stream ceiling before
opening a file or buffering output. Chunks go directly to exclusive fixed-name
files under the pinned directory. The store tracks metadata for interleaved
pending streams, charges failed/partial streams without refunds, and checks the
stream hash against held bytes before syncing and publishing a fact. An
unfinished stream prevents validation. Overflow retains only the bounded
available prefix; interruption retains already written evidence without
overwrite or deletion. Existing buffered `put` uses the same writer path.

The private `process_capture._capture` primitive accepts an invocation only from
trusted controller code. It has no customer route, runtime admission or fixed
Grype wrapper yet. It captures stdout and stderr to those streams using the
same source/config/ledger/deadline as earlier stages. Stdout is capped by the
configured diagnostic-file limit (at most64MiB); stderr is capped at256KiB or
that smaller configured limit. Full reservations count toward aggregate256MiB
retention before launching the child. No shell or stdin is used.

The selector loop polls deadline, source epoch and trusted cancellation even
after both pipes close while the leader remains alive. On uncertainty it kills
the process group, waits at most5s to reap the leader and refuses completion;
cleanup buys no further analysis. Pending partial files remain unadmitted.
Cancellation permanently refuses this store, including before launch. Missing
leader cleanup is an explicit refusal. The host must still enforce cgroup CPU,
memory, swap, PID and job-wall limits and drain the dedicated container; a
detached descendant is outside this primitive's process-group guarantee.

Complete captured bytes are retained for nonzero exits as well. A zero return
code proves only the observed leader exit, not valid JSON, an admitted report,
runtime/advisory identity, successful exact-ID recovery or a successful scan.
Capture's lifecycle label is deliberately `leader-reaped-only`. A future fixed
consumer controller must independently admit all those prerequisites and final
source/runtime/output state. Neither this helper nor a child record attests
parent-owned kernel or persistent custody.

Unit evidence uses finite trusted Python children to exercise exact captures,
nonzero exit, overflow, cancellation and closed-pipe live leaders. It is not
actual Grype integration, full hostile lifecycle acceptance or M046 completion.
