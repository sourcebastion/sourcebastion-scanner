"""Internal bounded pipe capture, before fixed runtime/host admission.

Only trusted controller code may construct invocations. This primitive neither
admits executables nor establishes kernel limits or all-descendant cleanup.
The host must drain the dedicated job container before accepting any report.
"""

from dataclasses import dataclass
import os
import selectors
import signal
import subprocess
from threading import Event
import time

from .artifacts import ArtifactFact, ArtifactStore
from .budget import PipelineBudget
from .inputs import InputRefusal


@dataclass(frozen=True)
class Capture:
    returncode: int
    stdout: ArtifactFact
    stderr: ArtifactFact
    lifecycle: str = "leader-reaped-only"


def _capture(
    command,
    *,
    source,
    config,
    budget,
    store,
    environment,
    cwd,
    cancelled=None,
    stdout_name="grype.json",
    stderr_name="grype.stderr",
    stdout_maximum=None,
    stderr_maximum=None,
    pass_fds=(),
):
    """Capture one trusted invocation without a fresh deadline or allowance.

    Exit zero establishes only the process exit code, not an admitted Grype
    result. Nonzero exits retain complete captured bytes too. Deadline,
    cancellation, pipe or output uncertainty leaves partial files unadmitted.
    ``cancelled`` is a trusted Event, never customer configuration or a callback.
    """
    if type(budget) is not PipelineBudget or type(store) is not ArtifactStore or store.check != budget.check:
        raise TypeError("controller-budget-and-store-required")
    if cancelled is not None and type(cancelled) is not Event:
        raise TypeError("controller-cancellation-event-required")
    budget.bind(source, config)
    store.require_source_separation(source)

    def tick():
        budget.check()
        if cancelled is not None and cancelled.is_set():
            store._refusal = store._refusal or "consumer-capture-cancelled"
            raise InputRefusal("consumer-capture-cancelled")

    tick()
    if type(pass_fds) is not tuple or any(type(value) is not int or value < 0 for value in pass_fds):
        raise TypeError("trusted-consumer-descriptors-required")
    out = store.writer(
        stdout_name, maximum=store.limits.diagnostic_file_bytes if stdout_maximum is None else stdout_maximum
    )
    err = store.writer(
        stderr_name,
        maximum=min(256 * 1024, store.limits.diagnostic_file_bytes) if stderr_maximum is None else stderr_maximum,
    )
    process = None
    try:
        tick()
        with selectors.DefaultSelector() as selector:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                cwd=cwd,
                start_new_session=True,
                close_fds=True,
                pass_fds=pass_fds,
            )
            for pipe, writer in ((process.stdout, out), (process.stderr, err)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, writer)
            while selector.get_map() or process.poll() is None:
                tick()
                remaining = max(0, budget.deadline - time.monotonic())
                if not selector.get_map():
                    # Keep checking after both pipes close: a live consumer can
                    # still consume CPU or ignore cancellation at this point.
                    time.sleep(min(0.05, remaining))
                    continue
                for key, _event in selector.select(min(0.1, remaining)):
                    raw = os.read(key.fd, 65536)
                    if raw:
                        key.data.write(raw)
                    else:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
            tick()
            result = Capture(process.returncode, out.finish(), err.finish())
            tick()
            store.validate()
            tick()
            return result
    except BaseException:
        store._refusal = store._refusal or "consumer-capture-failed"
        if process is not None:
            cleanup_failed = False
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                cleanup_failed = True
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                raise InputRefusal("consumer-leader-cleanup-unconfirmed") from None
            if cleanup_failed:
                raise InputRefusal("consumer-leader-cleanup-unconfirmed") from None
        raise
    finally:
        if process is not None:
            for pipe in (process.stdout, process.stderr):
                if pipe is not None:
                    pipe.close()
