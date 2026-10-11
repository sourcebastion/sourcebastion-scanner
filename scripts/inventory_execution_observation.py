"""Host process/network observations of a stopped, owned proof container.

Attach before the trusted shell is released, follow every fork/thread, and
detach only after its workload has exited. This records finite observations;
review of allowed invocations is separate from collecting the trace.
"""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

MAX_TRACE_BYTES = 8 * 1024**2


def records(raw):
    if len(raw) > MAX_TRACE_BYTES:
        raise ValueError("execution-observer-trace-bound")
    lines = raw.decode("utf-8", "strict").splitlines()
    executions = [line for line in lines if re.search(r"\bexecve(?:at)?(?:\(| resumed)", line)]
    for line in executions:
        record = re.sub(r"<unfinished \.\.\.>|<\.\.\. execve(?:at)? resumed>", "", line)
        if "..." in record:
            raise ValueError("execution-observer-truncated-execution-record")
    if not executions:
        raise ValueError("execution-observer-execution-records-missing")
    calls = {}
    for line in lines:
        match = re.match(r"\d+\s+([a-zA-Z0-9_]+)\(", line)
        if match:
            name = match.group(1)
            calls[name] = calls.get(name, 0) + 1
    return {"executions": executions,
            "inet_records": [line for line in lines if "AF_INET" in line],
            "syscall_counts": calls}


def proc_status(pid):
    raw = Path(f"/proc/{pid}/status").read_text()
    if len(raw) > 16384:
        raise ValueError("execution-observer-process-status-bound")
    return dict(line.split(":", 1) for line in raw.splitlines() if ":" in line)


def verify_observation(directory):
    trace = directory / "execution.trace"
    metadata = directory / "execution-observation.json"
    if trace.stat().st_size > MAX_TRACE_BYTES or metadata.stat().st_size > 2 * MAX_TRACE_BYTES:
        raise ValueError("execution-observer-retained-bound")
    raw = trace.read_bytes()
    value = json.loads(metadata.read_bytes())
    if (value.get("status") != "trace-collected-review-required"
            or value.get("attached_before_workload_release") is not True
            or value.get("detached_after_workload_exit") is not True
            or value.get("acceptance") is not False
            or value.get("trace_sha256") != hashlib.sha256(raw).hexdigest()
            or value.get("trace_bytes") != len(raw)
            or any(value.get(key) != item for key, item in records(raw).items())):
        raise ValueError("execution-observer-retained-binding-mismatch")
    return value["trace_sha256"]


def birth(pid):
    raw = Path(f"/proc/{pid}/stat").read_text()
    return raw[raw.rindex(")") + 2:].split()[19]


class ExecutionObservation:
    def __init__(self, output):
        self.output = output
        self.trace = output / "execution.trace"
        self.diagnostics = output / "execution-tracer.stderr"
        self.process = self.tracer = self.tracer_birth = None
        self.stream = None

    def workload_stopped(self, shell):
        status = proc_status(shell)
        if status["State"].strip().startswith("T"):
            return True
        # A ptraced SIGSTOP group-stop appears as lowercase t. A syscall
        # ptrace-stop also appears as t, so require strace's actual group-stop
        # record for this exact shell after the workload's exit gate exists.
        if (not status["State"].strip().startswith("t")
                or int(status["TracerPid"]) != self.tracer):
            return False
        with self.trace.open("rb") as stream:
            stream.seek(max(0, self.trace.stat().st_size - 4096))
            tail = stream.read(4096)
        return re.search(rb"(?:^|\n)" + str(shell).encode() + rb"\s+--- stopped by SIGSTOP ---\s*(?:\n|$)", tail) is not None

    def start(self, shell, deadline):
        status = proc_status(shell)
        if int(status["TracerPid"]) or not status["State"].strip().startswith("T"):
            raise ValueError("execution-observer-untraced-stopped-shell-required")
        # Precreate the private trace as the unprivileged maintainer so sudo's
        # tracer leaves a readable artifact without changing directory modes.
        with self.trace.open("xb"):
            pass
        self.stream = self.diagnostics.open("xb")
        self.process = subprocess.Popen(
            ["sudo", "-n", "strace", "-f", "-qq", "-s", "8192", "-yy",
             "-e", "trace=process,network", "-o", str(self.trace), "-p", str(shell)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=self.stream, start_new_session=True,
        )
        until = min(deadline, time.monotonic() + 10)
        while time.monotonic() < until:
            tracer = int(proc_status(shell)["TracerPid"])
            if tracer:
                self.tracer, self.tracer_birth = tracer, birth(tracer)
                return
            if self.process.poll() is not None:
                raise ValueError("execution-observer-attachment-failed")
            time.sleep(0.01)
        raise ValueError("execution-observer-attachment-deadline")

    def stop(self, *, completed=False):
        if self.process is None:
            return None
        alive = self.process.poll() is None
        if alive and self.tracer is not None:
            if birth(self.tracer) != self.tracer_birth:
                raise ValueError("execution-observer-tracer-identity-changed")
            subprocess.run(["sudo", "-n", "kill", "-INT", str(self.tracer)],
                           stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=5)
        elif alive:
            # Attachment never completed; reap the sudo command we created.
            self.process.terminate()
        code = self.process.wait(timeout=5)
        self.stream.close()
        self.process = None
        if not completed:
            return None
        if not alive:
            raise ValueError("execution-observer-ended-before-workload")
        if self.trace.stat().st_size > MAX_TRACE_BYTES or self.diagnostics.stat().st_size > 65536:
            raise ValueError("execution-observer-trace-bound")
        if code not in (0, 130, -2) or self.diagnostics.read_bytes():
            raise ValueError("execution-observer-tracer-error")
        raw = self.trace.read_bytes()
        result = {"schema_version": "m046.host-execution-observation/1",
                  "status": "trace-collected-review-required",
                  "attached_before_workload_release": True,
                  "detached_after_workload_exit": True,
                  "trace_scope": "all descendant process and network syscalls",
                  "trace_sha256": hashlib.sha256(raw).hexdigest(),
                  "trace_bytes": len(raw), **records(raw), "acceptance": False}
        (self.output / "execution-observation.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        return result
