"""Single synthetic candidate job inside a constrained, credential-free container.

The host sends heartbeats. Host death/disconnection and all deadlines terminate
the job; exiting the container's PID namespace also kills session-escaping tasks.
There is no source interpreter/install/network fallback.
"""

import json
import hashlib
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import sys
import time

OUTPUT = Path("/output")
WORK = Path("/work")


def drain_candidate():
    """Stop every candidate UID task in this dedicated PID namespace."""
    deadline = time.monotonic() + 5
    killed = set()
    while True:
        active = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                fields = dict(line.split(":", 1) for line in (entry / "status").read_text().splitlines() if ":" in line)
                if set(fields["Uid"].split()) == {"65534"} and not fields["State"].lstrip().startswith("Z"):
                    active.append(int(entry.name))
            except (FileNotFoundError, ProcessLookupError):
                continue
        if not active:
            return sorted(killed)
        for pid in active:
            try:
                os.kill(pid, signal.SIGKILL)
                killed.add(pid)
            except ProcessLookupError:
                pass
        if time.monotonic() >= deadline:
            raise RuntimeError("candidate namespace did not drain")
        time.sleep(0.01)


def capture_raw():
    """Snapshot one bounded regular result without following candidate links."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open(WORK, flags)
    try:
        fd = os.open("raw.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > 64 * 1024 * 1024:
                raise ValueError("raw result must be a regular file within 64MiB")
            content = bytearray()
            while len(content) <= 64 * 1024 * 1024:
                block = os.read(fd, min(1024 * 1024, 64 * 1024 * 1024 + 1 - len(content)))
                if not block:
                    break
                content.extend(block)
            after = os.fstat(fd)
            visible = os.stat("raw.json", dir_fd=parent, follow_symlinks=False)
            key = lambda value: (
                value.st_dev,
                value.st_ino,
                value.st_mode,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )
            if len(content) != before.st_size or key(before) != key(after) or key(before) != key(visible):
                raise ValueError("raw result changed during capture")
            with (OUTPUT / "raw.json").open("xb") as result:
                os.fchmod(result.fileno(), 0o644)
                result.write(content)
            return {"captured_raw_sha256": hashlib.sha256(content).hexdigest(), "captured_raw_bytes": len(content)}
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def heartbeat_alive():
    try:
        return time.time() - (OUTPUT / "heartbeat").stat().st_mtime < 5
    except FileNotFoundError:
        return False


def main():
    config = json.loads((OUTPUT / "launch.json").read_text())
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    signal.signal(signal.SIGTERM, lambda _signum, _frame: sys.exit(143))
    signal.signal(signal.SIGINT, lambda _signum, _frame: sys.exit(130))
    # Only /work is candidate-writable; no host output ancestor is writable.
    os.chown(OUTPUT, 0, 0)
    OUTPUT.chmod(0o755)
    for name in ("ready", "done", "result.json"):
        os.chown(OUTPUT / name, 0, 0)
        (OUTPUT / name).chmod(0o644)
    for name in ("ready", "done", "result.json", "go", "ack", "heartbeat", "launch.json"):
        metadata = (OUTPUT / name).lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid == 65534 or metadata.st_mode & 0o022:
            raise RuntimeError("controller marker is candidate-writable or not a regular file")
    os.chown(WORK, 65534, 65534)
    (OUTPUT / "ready").write_text("ready\n")
    waiting = time.monotonic()
    while (OUTPUT / "go").read_text().strip() != "go":
        if not heartbeat_alive() or time.monotonic() - waiting > 30:
            raise SystemExit(124)
        time.sleep(0.05)
    env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "TZ": "UTC",
        "NO_COLOR": "1",
        "HOME": "/tmp",
        "TMPDIR": "/tmp",
        "XDG_CACHE_HOME": "/tmp/cache",
        "SYFT_CHECK_FOR_APP_UPDATE": "false",
        "SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true",
        "CDXGEN_NO_PROGRESS": "true",
        "CDXGEN_TIMEOUT_MS": "30000",
        "CDXGEN_PYPI_METADATA": "false",
        "FETCH_LICENSE": "false",
    }
    started = time.monotonic()
    with (OUTPUT / "stdout.log").open("xb") as stdout, (OUTPUT / "stderr.log").open("xb") as stderr:
        os.fchmod(stdout.fileno(), 0o644)
        os.fchmod(stderr.fileno(), 0o644)
        process = subprocess.Popen(
            config["command"],
            cwd="/source",
            env=env,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
            user=65534,
            group=65534,
            extra_groups=[],
        )
        reason = None
        while process.poll() is None:
            if not heartbeat_alive():
                reason = "host-heartbeat-expired"
                break
            if time.monotonic() - started > config["wall_limit_seconds"]:
                reason = "wall-budget-exceeded"
                break
            time.sleep(0.02)
        if reason:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        drained = drain_candidate()
        if drained and reason is None:
            reason = "descendant-work-after-leader-exit"
        result = {
            "exit_code": process.returncode,
            "reason": reason,
            "wall_seconds": time.monotonic() - started,
            "python_version": sys.version,
            "drained_candidate_pids": drained,
        }
        try:
            result.update(capture_raw())
        except (OSError, ValueError) as error:
            result["capture_error"] = str(error)
        result["wall_seconds"] = time.monotonic() - started
    (OUTPUT / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    (OUTPUT / "done").write_text("done\n")
    # Keep the cgroup alive for exact final counters. Never live indefinitely
    # if the measuring driver dies or fails to acknowledge the completed job.
    waiting = time.monotonic()
    while (OUTPUT / "ack").read_text().strip() != "ack":
        if not heartbeat_alive() or time.monotonic() - waiting > 15:
            break
        time.sleep(0.05)


if __name__ == "__main__":
    main()
