"""Opt-in native Docker proofs using only supervisor-owned synthetic programs.

These programs are harness probes, not repository code or inventory candidates.
They prove real UID/capability, mount, watchdog and cleanup behavior. They do not
accept performance budgets, inventory coverage, or a production sandbox.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time
import uuid

from . import benchmark
from .run import digest

PROGRAM = r"""
import json, os, socket, subprocess, sys, time
from pathlib import Path
import platform
mode = Path('/source/mode').read_text().strip()
result = {'uid':os.geteuid(), 'status':Path('/proc/self/status').read_text()}
if mode == 'boundaries':
    attempts={}
    for name in ('/source/mutation', '/output/measurement.json', '/output/go', '/output/ack', '/output/heartbeat', '/output/result.json'):
        try:
            Path(name).write_text('forged')
            attempts[name]='accepted'
        except OSError as error:
            attempts[name]=error.errno
    sock=socket.socket()
    sock.settimeout(.5)
    try:
        sock.connect(('192.0.2.1',443))
        attempts['network']='accepted'
    except OSError as error:
        attempts['network']=error.errno
    finally:
        sock.close()
    result['attempts']=attempts
if mode in ('escape', 'watchdog', 'driver-death'):
    child=subprocess.Popen([sys.executable,'-c',"import os,time; from pathlib import Path; Path('/work/child-ready').write_text(str(os.getpid())); time.sleep(300)"],start_new_session=True)
    until=time.monotonic()+5
    while not Path('/work/child-ready').exists():
        assert time.monotonic()<until
        time.sleep(.01)
    result['escaped_child_pid']=child.pid
if mode == 'symlink':
    os.symlink('/source/private-sentinel','/work/raw.json')
else:
    Path('/work/raw.json').write_text(json.dumps(result))
if mode in ('watchdog','driver-death'):
    time.sleep(300)
if mode == 'cpu':
    while True:
        sum(range(100000))
if mode == 'memory':
    blocks=[]
    while True:
        blocks.append(bytearray(16*1024*1024))
if mode == 'tmpfs':
    total=0
    filesystem=os.statvfs('/work')
    capacity=filesystem.f_frsize*filesystem.f_blocks
    try:
        for number in range(6):
            with open('/work/blob'+str(number),'wb') as stream:
                for _ in range(60):
                    total+=stream.write(b'x'*1024*1024)
    except OSError as error:
        Path('/work/raw.json').write_text(json.dumps({'errno':error.errno,'bytes_written':total,'capacity_bytes':capacity}))
"""


def prepare_python(output):
    name = "m046-proof-prepare-" + uuid.uuid4().hex
    try:
        identifier = benchmark.docker(
            "create",
            "--platform",
            "linux/" + {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()],
            "--name",
            name,
            "--entrypoint",
            "/bin/true",
            benchmark.IMAGE,
        )
        binary = output / "proof-python"
        benchmark.docker("cp", identifier + ":/usr/local/bin/python3.14", str(binary))
        binary.chmod(0o755)
        benchmark.native_elf(binary)
        return {"binary": str(binary), "sha256": digest(binary)}
    finally:
        subprocess.run([*benchmark.DOCKER, "rm", "--force", name], check=True, capture_output=True, timeout=30)


def run_case(root, tool, mode):
    source = root / (mode + "-source")
    source.mkdir()
    (source / "probe.py").write_text(PROGRAM)
    (source / "mode").write_text(mode)
    (source / "private-sentinel").write_text("synthetic evidence only")
    original = benchmark.command
    benchmark.command = lambda *_args: ["/candidate/binary", "/source/probe.py"]
    try:
        return benchmark.measure("syft", tool, source, root / mode, "python")
    finally:
        benchmark.command = original


def main():
    if not __debug__:
        raise RuntimeError("proofs require assertions enabled; optimized execution is refused")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    args.output.chmod(0o700)
    tool = prepare_python(args.output)
    results = {}
    previous_umask = os.umask(0)
    try:
        result = run_case(args.output, tool, "boundaries")
        data = json.loads((args.output / "boundaries/controller/raw.json").read_text())
        assert data["uid"] == 65534
        capabilities = next(line for line in data["status"].splitlines() if line.startswith("CapEff:"))
        assert int(capabilities.split()[1], 16) == 0
        assert all(value != "accepted" for value in data["attempts"].values())
        assert result["resource_sample_valid"] and result["source_unchanged"]
        results["boundaries_umask000"] = result
    finally:
        os.umask(previous_umask)
    escaped = run_case(args.output, tool, "escape")
    assert escaped["reason"] == "descendant-work-after-leader-exit" and escaped["drained_candidate_pids"]
    assert not escaped["resource_sample_valid"]
    results["session_escape"] = escaped
    previous_wall = benchmark.WALL_SECONDS
    benchmark.WALL_SECONDS = 1
    try:
        watchdog = run_case(args.output, tool, "watchdog")
        assert watchdog["reason"] == "wall-budget-exceeded" and not watchdog["resource_sample_valid"]
        assert watchdog["drained_candidate_pids"]
        results["watchdog_cap_kill"] = watchdog
    finally:
        benchmark.WALL_SECONDS = previous_wall
    symlink = run_case(args.output, tool, "symlink")
    assert "capture_error" in symlink and not symlink["resource_sample_valid"]
    assert not (args.output / "symlink/controller/raw.json").exists()
    results["raw_symlink_refused"] = symlink
    previous_cpu = benchmark.CPU_SECONDS
    benchmark.CPU_SECONDS = 0.25
    try:
        cpu = run_case(args.output, tool, "cpu")
        assert cpu["driver_reason"] == "cpu-budget-exceeded" and "cpu" in cpu["exceeded_budgets"]
        assert not cpu["resource_sample_valid"]
        results["aggregate_cpu_watchdog"] = cpu
    finally:
        benchmark.CPU_SECONDS = previous_cpu
    memory = run_case(args.output, tool, "memory")
    assert memory["memory_counters"]["oom_kills"] > memory["initial_counters"]["oom_kills"]
    assert "memory" in memory["exceeded_budgets"] and not memory["resource_sample_valid"]
    results["kernel_memory_overflow"] = memory
    tmpfs = run_case(args.output, tool, "tmpfs")
    tmpfs_data = json.loads((args.output / "tmpfs/controller/raw.json").read_text())
    assert tmpfs_data["errno"] == 28 and tmpfs_data["bytes_written"] <= 256 * 1024 * 1024
    assert tmpfs_data["capacity_bytes"] == 256 * 1024 * 1024
    results["candidate_tmpfs_overflow"] = tmpfs
    pid = os.fork()
    if pid == 0:
        try:
            run_case(args.output, tool, "driver-death")
        finally:
            os._exit(0)
    control = args.output / "driver-death/controller"
    deadline = time.monotonic() + 30
    identifier = None
    try:
        while not (control / "go").exists() or (control / "go").read_text().strip() != "go":
            assert time.monotonic() < deadline
            time.sleep(0.05)
        # Find only this driver's exact bind path; unrelated containers are untouched.
        for item in benchmark.docker("ps", "--quiet").splitlines():
            inspection = json.loads(benchmark.docker("inspect", item))[0]
            if any(mount["Source"] == str(control.resolve()) for mount in inspection["Mounts"]):
                identifier = inspection["Id"]
                break
        assert identifier
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        while json.loads(benchmark.docker("inspect", identifier))[0]["State"]["Running"]:
            assert time.monotonic() < deadline
            time.sleep(0.1)
        final = json.loads(benchmark.docker("inspect", identifier))[0]
        assert final["State"]["Pid"] == 0
        watchdog_result = json.loads((control / "result.json").read_text())
        assert watchdog_result["reason"] == "host-heartbeat-expired"
        results["driver_sigkill"] = {
            "container_id": identifier,
            "final_state": final["State"],
            "controller_result": watchdog_result,
            "automatic_process_cleanup": True,
            "docker_object_cleanup": "explicit after stopped-state proof",
        }
    finally:
        if identifier:
            benchmark.docker("rm", "--force", identifier)
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
    report = {
        "status": "native-harness-proofs; no inventory/performance acceptance",
        "harness_sha256": digest(benchmark.__file__),
        "controller_sha256": digest(Path(benchmark.__file__).with_name("container_job.py")),
        "cgroup_reader_sha256": digest(Path(benchmark.__file__).with_name("cgroup_metrics.py")),
        "performance_corpus_sha256": digest(Path(benchmark.__file__).with_name("performance_corpus.py")),
        "probe_python_sha256": tool["sha256"],
        "python_optimization": sys.flags.optimize,
        "invocation": sys.argv,
        "results": results,
    }
    (args.output / "proofs.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"proofs_passed": list(results), "report": str(args.output / "proofs.json")}, indent=2))


if __name__ == "__main__":
    main()
