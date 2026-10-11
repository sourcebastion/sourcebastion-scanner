"""Missing/truncated traces cannot substitute for observed execution facts."""

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import inventory_execution_observation as observation
from inventory_execution_observation import records


def test_observation_keeps_failed_network_attempts_and_split_exec_records():
    raw = b'''123 execve("/usr/local/bin/python3", ["python3", "-I", "-m", "sourcebastion.inventory_entrypoint"], 0x123 /* 2 vars */ <unfinished ...>
123 <... execve resumed>) = 0
124 socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP) = -1 EPERM (Operation not permitted)
124 connect(3, {sa_family=AF_INET, sin_port=htons(443)}, 16) = -1 ENETUNREACH (Network is unreachable)
'''
    result = records(raw)
    assert len(result["executions"]) == 2
    assert len(result["inet_records"]) == 2
    assert result["syscall_counts"]["connect"] == 1


@pytest.mark.parametrize("raw", [b"", b"123 wait4(124, NULL, 0, NULL) = 124\n",
    b'123 execve("/source/setup.py", ["/source/setup.py", ...], 0x123) = 0\n',
    b'123 execve("/source/setup.py", ["argument"...], 0x123) = 0\n', b"\xff"])
def test_incomplete_observations_refuse(raw):
    with pytest.raises((ValueError, UnicodeDecodeError)):
        records(raw)


@pytest.mark.parametrize("state,tracer,trace,expected", [
    ("T (stopped)", "0", b"", True),
    ("t (tracing stop)", "99", b"123 --- stopped by SIGSTOP ---\n", True),
    ("t (tracing stop)", "99", b"123 execve(\"/installed/tool\", [], 0x123) = 0\n", False),
    ("t (tracing stop)", "98", b"123 --- stopped by SIGSTOP ---\n", False),
    ("t (tracing stop)", "99", b"124 --- stopped by SIGSTOP ---\n", False),
    ("R (running)", "99", b"123 --- stopped by SIGSTOP ---\n", False),
])
def test_traced_group_stop_is_distinct_from_an_intermediate_syscall_stop(tmp_path, monkeypatch, state, tracer, trace, expected):
    observer = observation.ExecutionObservation(tmp_path)
    observer.tracer = 99
    observer.trace.write_bytes(trace)
    monkeypatch.setattr(observation, "proc_status", lambda _pid: {"State": state, "TracerPid": tracer})
    assert observer.workload_stopped(123) is expected
