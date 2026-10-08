"""Actual finite children exercise pipe EOF, overflow and cancellation."""

from contextlib import contextmanager
import os
import sys
from threading import Event, Timer
import time

import pytest

from sourcebastion.inventory.artifacts import ArtifactStore
from sourcebastion.inventory.budget import PipelineBudget
from sourcebastion.inventory.contract import InventoryLimits
from sourcebastion.inventory.inputs import InputRefusal, Source
from sourcebastion.inventory.process_capture import _capture
from sourcebastion.inventory.registry import DiscoveryConfig


@contextmanager
def context(tmp_path, *, seconds=10, **limits):
    root, output = tmp_path / "source", tmp_path / "output"
    root.mkdir()
    output.mkdir(mode=0o700)
    config = DiscoveryConfig()
    with Source(root) as source:
        budget = PipelineBudget(source, config=config, deadline=time.monotonic() + seconds)
        with ArtifactStore(output, limits=InventoryLimits(**limits), check=budget.check) as store:
            yield source, budget, config, store


def capture(code, source, budget, config, store, *, cancelled=None):
    return _capture(
        [sys.executable, "-I", "-c", code],
        source=source,
        budget=budget,
        config=config,
        store=store,
        environment={"PATH": "/usr/bin:/bin", "HOME": "/tmp"},
        cwd="/tmp",
        cancelled=cancelled,
    )


def child_code(pidfile, body):
    return "import os,time; open(" + repr(str(pidfile)) + ", 'w').write(str(os.getpid())); " + body


def assert_reaped(pidfile):
    pid = int(pidfile.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_capture_preserves_exact_stdout_stderr_but_asserts_no_report_admission(tmp_path):
    with context(tmp_path, diagnostic_file_bytes=1024) as values:
        source, budget, config, store = values
        result = capture("import os; os.write(1,b' {\"matches\": []} \\n'); os.write(2,b'notice\\n')", *values)
        assert result.returncode == 0 and result.lifecycle == "leader-reaped-only"
        assert (store.root / "grype.json").read_bytes() == b' {"matches": []} \n'
        assert (store.root / "grype.stderr").read_bytes() == b"notice\n"
        assert result.stdout.bytes == 18 and result.stderr.bytes == 7
        assert store.reserved_bytes == 2048 and len(store.facts) == 2
        assert budget.consumed > 0


def test_nonzero_consumer_preserves_complete_captured_files(tmp_path):
    with context(tmp_path, diagnostic_file_bytes=1024) as values:
        result = capture("import os; os.write(1,b'partial-json'); os.write(2,b'failed'); raise SystemExit(7)", *values)
        assert result.returncode == 7 and result.stdout.bytes == 12 and result.stderr.bytes == 6
        assert len(values[3].facts) == 2


def test_overflow_retains_prefix_and_kills_reaps_leader(tmp_path):
    pidfile = tmp_path / "pid"
    with context(tmp_path, diagnostic_file_bytes=1024) as values:
        code = child_code(pidfile, "os.write(1,b'x'*200000); time.sleep(20)")
        with pytest.raises(InputRefusal, match="artifact-stream-budget-exceeded"):
            capture(code, *values)
        store = values[3]
        assert (store.root / "grype.json").read_bytes() == b"x" * 1024
        assert not store.facts and store.reserved_bytes == 2048
        assert_reaped(pidfile)


def test_deadline_still_checked_when_both_pipes_close_but_child_lives(tmp_path):
    pidfile = tmp_path / "pid"
    with context(tmp_path, seconds=0.5, diagnostic_file_bytes=1024) as values:
        code = child_code(pidfile, "os.close(1); os.close(2); time.sleep(20)")
        start = time.monotonic()
        with pytest.raises(InputRefusal, match="deadline-exceeded"):
            capture(code, *values)
        assert time.monotonic() - start < 3
        assert not values[3].facts
        assert_reaped(pidfile)


def test_cancellation_still_checked_when_closed_pipe_child_consumes_cpu(tmp_path):
    pidfile = tmp_path / "pid"
    event = Event()
    timer = Timer(0.4, event.set)
    with context(tmp_path, diagnostic_file_bytes=1024) as values:
        code = child_code(pidfile, "os.close(1); os.close(2)\nwhile True: pass")
        timer.start()
        try:
            with pytest.raises(InputRefusal, match="consumer-capture-cancelled"):
                capture(code, *values, cancelled=event)
        finally:
            timer.cancel()
            timer.join()
        assert_reaped(pidfile)
        assert not values[3].facts


def test_cancelled_job_never_launches_consumer(tmp_path):
    pidfile = tmp_path / "pid"
    event = Event()
    event.set()
    with context(tmp_path, diagnostic_file_bytes=1024) as values:
        with pytest.raises(InputRefusal, match="consumer-capture-cancelled"):
            capture(child_code(pidfile, "pass"), *values, cancelled=event)
        assert not pidfile.exists() and not list(values[3].root.iterdir())
        event.clear()
        with pytest.raises(InputRefusal, match="consumer-capture-cancelled"):
            values[3].validate()


def test_cancellation_during_final_rehash_refuses_success_and_stays_sticky(tmp_path, monkeypatch):
    event = Event()
    original_pread = os.pread
    injected = False
    with context(tmp_path, diagnostic_file_bytes=1024) as values:
        store = values[3]

        def cancel_during_final_rehash(descriptor, size, offset):
            nonlocal injected
            raw = original_pread(descriptor, size, offset)
            if len(store.facts) == 2 and not store._pending:
                injected = True
                event.set()
            return raw

        monkeypatch.setattr(os, "pread", cancel_during_final_rehash)
        with pytest.raises(InputRefusal, match="consumer-capture-cancelled"):
            capture("import os; os.write(1,b'complete'); os.write(2,b'notice')", *values, cancelled=event)
        assert injected and len(store.facts) == 2
        assert (store.root / "grype.json").read_bytes() == b"complete"
        event.clear()
        with pytest.raises(InputRefusal, match="consumer-capture-cancelled"):
            store.validate()


def test_reservation_failure_never_launches_consumer(tmp_path):
    pidfile = tmp_path / "pid"
    with context(tmp_path, diagnostic_file_bytes=1024, diagnostic_job_bytes=2000) as values:
        with pytest.raises(InputRefusal, match="artifact-retention-budget-exceeded"):
            capture(child_code(pidfile, "pass"), *values)
        assert not pidfile.exists() and not values[3].facts


def test_source_root_change_during_capture_refuses_success(tmp_path):
    pidfile = tmp_path / "pid"
    with context(tmp_path, diagnostic_file_bytes=1024) as values:
        path = values[0].root / "unexpected"
        code = child_code(pidfile, "open(" + repr(str(path)) + ", 'w').write('change'); time.sleep(20)")
        with pytest.raises(InputRefusal, match="changed-source-root"):
            capture(code, *values)
        assert_reaped(pidfile)
        assert not values[3].facts
