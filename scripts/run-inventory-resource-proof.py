"""Finite native CI cgroup-v2 observer; never a production admission service.

The stopped trusted shell keeps the fresh job cgroup alive for a final host
read. All child processes charge that one cgroup. Missing observations refuse
the proof. Docker Desktop/remote daemons cannot provide local host evidence.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import time
from inventory_release import FROZEN, measured_resources, policy
from inventory_execution_observation import ExecutionObservation


#: Retained diagnostics are bounded. The workloads are reviewed maintainer
#: scripts rather than customer code, so their messages are safe to record.
DETAIL_BYTES = 2048


def docker(*args, seconds=15):
    result = subprocess.run(["docker", *args], stdin=subprocess.DEVNULL, capture_output=True, timeout=seconds, check=True)
    if len(result.stdout) > 65536 or len(result.stderr) > 65536:
        raise ValueError("resource-driver-control-bound")
    return result.stdout


def read_bytes(raw):
    """The integer a docker command printed, or a refusal naming what it said."""
    text = raw.decode("utf-8", "replace").strip() if isinstance(raw, bytes) else str(raw).strip()
    try:
        return int(text)
    except ValueError:
        raise ValueError("resource-container-exit-unreadable") from None


def read(path):
    raw = path.read_text()
    if len(raw) > 4096:
        raise ValueError("resource-kernel-record-bound")
    return raw.strip()


def counters(path):
    return {key: int(number) for key, number in (line.split() for line in read(path).splitlines())}


def cgroup(pid):
    raw = read(Path(f"/proc/{pid}/cgroup"))
    rows = raw.splitlines()
    if len(rows) != 1 or not rows[0].startswith("0::/"):
        raise ValueError("local-unified-cgroup-required")
    relative = rows[0][4:]
    if ".." in relative.split("/") or not relative:
        raise ValueError("dedicated-container-cgroup-required")
    return Path("/sys/fs/cgroup") / relative


def limits(root):
    quota, period = read(root / "cpu.max").split()
    if quota == "max" or int(quota) > 2 * int(period) or int(quota) <= 0:
        raise ValueError("resource-cpu-quota-mismatch")
    if (read(root / "memory.max") != str(FROZEN["memory_bytes"])
            or read(root / "memory.swap.max") != "0"
            or read(root / "pids.max") != str(FROZEN["pids"])):
        raise ValueError("resource-kernel-limit-mismatch")


def observe(root):
    return {
        "cpu_usec": counters(root / "cpu.stat")["usage_usec"],
        "memory_peak": int(read(root / "memory.peak")),
        # Disabled swap cannot have hidden intermediate swap usage.
        "swap_peak": int(read(root / "memory.swap.current")),
        "pids_peak": int(read(root / "pids.peak")),
        "oom_kill": counters(root / "memory.events")["oom_kill"],
    }


def run(args):
    policy()
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if platform.system() != "Linux" or architecture is None:
        raise ValueError("native-linux-host-required")
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    gate = args.output / "gate"
    gate.mkdir(mode=0o700)
    receipt = {"schema_version": "m046.host-resource-proof/1", "observer": "host-cgroup-v2",
               "architecture": architecture, "status": "failed", "removed": False,
               "scope": "Finite native CI workload; no production custody/administrator-fencing or M046 acceptance."}
    cid, root, original = None, None, {}
    trace = ExecutionObservation(args.output) if args.observe_execution else None
    started = time.monotonic()
    deadline = started + FROZEN["wall_seconds"]
    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise TimeoutError("resource-shared-wall-deadline")
        return min(15, seconds)
    def interrupted(*_args):
        raise InterruptedError("resource-parent-interrupted")
    for signum in (signal.SIGTERM, signal.SIGINT):
        original[signum] = signal.signal(signum, interrupted)
    try:
        image = json.loads(docker("image", "inspect", args.image, seconds=remaining()))[0]
        if image["Architecture"] != architecture or image["Os"] != "linux":
            raise ValueError("resource-native-image-required")
        receipt["image_id"] = image["Id"]
        cidfile = args.output / "container.cid"
        options = ["create", "--cidfile", str(cidfile), "--init", "--no-healthcheck", "--network", "none", "--read-only",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", f"{os.getuid()}:{os.getgid()}",
                   "--cpus", "2", "--memory", "2g", "--memory-swap", "2g", "--pids-limit", "256",
                   "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m", "-e", "PYTHONPATH=", "-e", "GOMAXPROCS=2",
                   "-v", str(args.checkout.resolve()) + ":/repo:ro", "-w", "/repo",
                   "-v", str(gate.resolve()) + ":/gate:rw"]
        if args.provider:
            options += ["-v", str(args.provider.resolve()) + ":/prepared:ro"]
        # No project command is accepted here. The workload is a reviewed
        # installed-engine proof script fixed by this trusted maintainer CLI.
        command = ["python3", "scripts/verify-inventory-expectations.py", "--go-binary", "/usr/local/bin/sourcebastion-go-source",
                   "--go-preparation", "/prepared/manifest.json" if args.provider else
                   "/usr/local/share/sourcebastion/inventory-go.json", "--upgrade-report"]
        if args.workload == "stress":
            command = ["python3", "scripts/verify-inventory-stress.py", "--arm", args.arm]
        if args.workload in {"packaging", "cyclonedx"}:
            command = ["python3", f"scripts/verify-inventory-{args.workload}.py"]
        if args.workload == "entrypoint":
            for name, destination, mode in (("source", "/source", "ro"), ("advisories", "/advisories", "ro"),
                                           ("preparation", "/preparation", "ro"), ("control", "/control", "ro"),
                                           ("artifacts", "/out", "rw")):
                path = getattr(args, name).resolve(strict=True)
                options += ["-v", f"{path}:{destination}:{mode}"]
            control = json.loads((args.control / "job.json").read_text())
            if type(control["deadline_monotonic"]) not in (int, float):
                raise ValueError("entrypoint-original-deadline-required")
            deadline = min(deadline, control["deadline_monotonic"])
            command = ["python3", "-I", "-m", "sourcebastion.inventory_entrypoint"]
        wrapper = 'kill -STOP $$; "$@"; result=$?; printf "%s" "$result" > /gate/exit; kill -STOP $$; exit "$result"'
        try:
            docker(*options, "--entrypoint", "/bin/sh", image["Id"], "-c", wrapper, "inventory-proof", *command, seconds=remaining())
        finally:
            # A timed-out create may already have allocated a container.
            if cidfile.is_file() and not cidfile.is_symlink():
                candidate = read(cidfile)
                if len(candidate) == 64 and all(c in "0123456789abcdef" for c in candidate):
                    cid = candidate
        if cid is None:
            raise ValueError("resource-owned-container-required")
        receipt["container_id"] = cid
        docker("start", cid, seconds=remaining())
        inspect = json.loads(docker("inspect", cid, seconds=remaining()))[0]
        if inspect["Image"] != image["Id"] or not inspect["State"]["Running"]:
            raise ValueError("resource-container-identity-mismatch")
        pid = inspect["State"]["Pid"]
        root = cgroup(pid)
        receipt["cgroup"] = str(root)
        limits(root)
        observe(root)  # All required kernel counters must exist before work.
        # PID-namespace init ignores self-sent SIGSTOP. Docker's tiny init is
        # PID1; the trusted shell is its one child, and CONT is forwarded to it.
        shell = None
        while shell is None:
            children = read(Path(f"/proc/{pid}/task/{pid}/children")).split()
            if len(children) == 1:
                shell = int(children[0])
            elif len(children) > 1:
                raise ValueError("resource-trusted-shell-identity-mismatch")
            remaining()
            time.sleep(0.01)
        while "State:\tT" not in read(Path(f"/proc/{shell}/status")):
            remaining()
            time.sleep(0.01)
        if trace is not None:
            trace.start(shell, deadline)
        docker("kill", "--signal", "CONT", cid, seconds=remaining())
        while not (gate / "exit").exists():
            remaining()
            sample = observe(root)
            receipt.update(sample)
            if sample["cpu_usec"] > FROZEN["cpu_usec"] or sample["oom_kill"]:
                raise ValueError("resource-kernel-budget-exceeded")
            if not Path(f"/proc/{pid}").exists():
                raise ValueError("resource-container-exited-without-final-observation")
            time.sleep(0.02)
        # Creating the exit file precedes both printf completing and SIGSTOP.
        # Observe the second stop before reading it or sending CONT, otherwise
        # an early CONT can be lost and leave the shell stopped forever.
        while not (trace.workload_stopped(shell) if trace is not None
                   else "State:\tT" in read(Path(f"/proc/{shell}/status"))):
            remaining()
            time.sleep(0.01)
        receipt.update(observe(root))
        limits(root)
        receipt["exit_code"] = int(read(gate / "exit"))
        receipt["wall_seconds"] = time.monotonic() - started
        if trace is not None:
            receipt["execution_observation"] = trace.stop(completed=True)
        # Every cgroup counter has now been read while the container is still
        # held, so the workload may be released. It must be: a held container
        # has not committed its stream, and `docker logs` returns nothing for
        # output below a buffer threshold measured locally at between 4 KiB
        # and 64 KiB. That silently lost the dependency job's receipt -- a few
        # hundred bytes -- while the large stress and corpus reports came
        # through, so the defect looked workload-specific rather than size
        # dependent.
        docker("kill", "--signal", "CONT", cid, seconds=remaining())
        waited = read_bytes(docker("wait", cid, seconds=remaining()))
        # The wrapper exits with the workload's status, so the container's
        # status must agree with the gate file the workload wrote. A
        # disagreement means the lifecycle is not what this proof reports.
        if waited != receipt["exit_code"]:
            raise ValueError("resource-container-exit-disagrees-with-workload")
        # Stream complete bounded workload output; a partial stream fails.
        with (args.output / "workload.json").open("xb") as stdout, (args.output / "workload.stderr").open("xb") as stderr:
            process = subprocess.Popen(["docker", "logs", cid], stdout=stdout, stderr=stderr)
            try:
                while process.poll() is None:
                    remaining()
                    if stdout.tell() > 64 * 1024**2 or stderr.tell() > 65536:
                        raise ValueError("resource-workload-output-bound")
                    time.sleep(0.02)
                if process.returncode != 0 or stdout.tell() > 64 * 1024**2 or stderr.tell() > 65536:
                    raise ValueError("resource-workload-output-failed")
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
        # A clean cgroup measurement of a workload that emitted nothing attests
        # nothing, and the digest of empty bytes must never be retained as
        # evidence that something ran. Every admitted workload -- corpus,
        # stress and entrypoint -- reports on stdout, including when it refuses.
        if (args.output / "workload.json").stat().st_size == 0:
            raise ValueError("resource-workload-output-empty")
        receipt["workload_sha256"] = hashlib.sha256((args.output / "workload.json").read_bytes()).hexdigest()
    except Exception as error:
        code = str(error)
        # `reason` stays a stable machine-readable code, so a caller can keep
        # matching on `resource-*`. `detail` carries what used to be thrown
        # away: an unexpected failure previously collapsed to its class name,
        # which told a reader the shape of the error and nothing about it.
        if type(error) in (ValueError, TimeoutError) and code.startswith("resource-"):
            receipt["reason"] = code
        else:
            receipt["reason"] = type(error).__name__
            receipt["detail"] = code[:DETAIL_BYTES] or "<no message>"
    finally:
        if trace is not None:
            try:
                trace.stop()
            except Exception as cleanup:
                receipt["reason"] = "execution-observer-cleanup-failed"
                receipt["detail"] = str(cleanup)[:DETAIL_BYTES]
        if cid is not None:
            try:
                docker("rm", "--force", cid, seconds=20)
                receipt["removed"] = True
            except Exception as cleanup:
                receipt["reason"] = "owned-container-cleanup-failed"
                receipt["detail"] = str(cleanup)[:DETAIL_BYTES] or type(cleanup).__name__
        for signum, handler in original.items():
            signal.signal(signum, handler)
    if "reason" not in receipt:
        try:
            measured_resources(receipt)
            receipt["status"] = "passed"
        except (ValueError, KeyError) as error:
            # A budget refusal names which ceiling; a KeyError names the
            # missing counter. Both were previously reduced to a class name.
            receipt["reason"] = type(error).__name__
            receipt["detail"] = str(error)[:DETAIL_BYTES] or "<no message>"
    (args.output / "resources.json").write_text(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["status"] == "passed" else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--checkout", required=True, type=Path)
    parser.add_argument("--provider", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--workload", choices=("corpus", "stress", "entrypoint", "packaging", "cyclonedx"), default="corpus")
    parser.add_argument("--observe-execution", action="store_true")
    for name in ("source", "advisories", "preparation", "control", "artifacts"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--arm", choices=("flat-1000", "flat-10000", "flat-100000", "flat-100001", "graph", "expansion"), default="flat-1000")
    args = parser.parse_args(argv)
    if args.workload == "entrypoint" and os.environ.get("SOURCEBASTION_NATIVE_OBSERVE_EXECUTION") == "1":
        args.observe_execution = True
    if args.workload == "entrypoint" and any(getattr(args, name) is None for name in ("source", "advisories", "preparation", "control", "artifacts")):
        parser.error("entrypoint requires all immutable controller mounts")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
