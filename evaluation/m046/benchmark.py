"""Untraced, aggregate-cgroup synthetic measurements; never engine acceptance."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import struct
import subprocess
import time
import uuid

from .cgroup_metrics import counters, group_paths, enforcement
from .performance_corpus import SPECS, generate
from .run import digest, snapshot, tree_digest
from .pack_evidence import read_regular

IMAGE = "python:3.14.8-bookworm@sha256:201c5349baecb1f46283454aa2ca2226301e60795cac68627a5a4b0cc9daed1b"
CPU_SECONDS = 120
WALL_SECONDS = 150
MEMORY_BYTES = 2 * 1024 * 1024 * 1024
DOCKER = ["docker", "--host", "unix:///var/run/docker.sock"]
SYFT_CONTROL_ENGINES = {"syft-control-cpe-on": True, "syft-control-cpe-off": False}
SYFT_RUNTIME_ENGINE = "syft-runtime-static"


def docker(*arguments):
    return subprocess.check_output([*DOCKER, *arguments], text=True, timeout=120).strip()


def native_elf(path):
    with Path(path).open("rb") as binary:
        header = binary.read(20)
    native = {"x86_64": 62, "aarch64": 183}[platform.machine()]
    if len(header) != 20 or header[:6] != b"\x7fELF\x02\x01" or struct.unpack("<H", header[18:20])[0] != native:
        raise ValueError("candidate executable must be native 64-bit little-endian ELF")


def budget_overruns(result, metrics, baseline):
    exceeded = []
    if result["aggregate_cpu_seconds"] > CPU_SECONDS:
        exceeded.append("cpu")
    if max(result.get("wall_seconds", 0), result["measured_job_wall_seconds"]) > WALL_SECONDS:
        exceeded.append("wall")
    if (
        metrics["peak_charged_memory_bytes"] > MEMORY_BYTES
        or metrics.get("oom_kills", 0) > baseline.get("oom_kills", 0)
        or metrics.get("memory_limit_failures", 0) > baseline.get("memory_limit_failures", 0)
    ):
        exceeded.append("memory")
    return exceeded


def command(engine, source_tool):
    raw = "/work/raw.json"
    if engine in SYFT_CONTROL_ENGINES or engine == SYFT_RUNTIME_ENGINE:
        return [
            "/usr/local/bin/python3",
            "-I",
            "-B",
            "/harness/syft_control_job.py",
            "extended" if engine == SYFT_RUNTIME_ENGINE else "on" if SYFT_CONTROL_ENGINES[engine] else "off",
        ]
    if engine == "syft":
        return [
            "/candidate/binary",
            "scan",
            "dir:/source",
            "--base-path",
            "/source",
            "--parallelism",
            "2",
            "-o",
            "syft-json=" + raw,
        ]
    if engine == "scalibr":
        return [
            "/candidate/binary",
            "--root",
            "/source",
            "--offline",
            "--plugins",
            "python,javascript",
            "--max-file-size",
            str(2 * 1024 * 1024),
            "--deterministic-ids",
            "-o",
            "cdx-json=" + raw,
        ]
    return [
        "/candidate/app/node_modules/.bin/node-real",
        "/candidate/app/bin/cdxgen.js",
        "/source",
        "-t",
        source_tool,
        "--no-install-deps",
        "--no-cache",
        "--no-progress",
        "--no-introspect",
        "--no-rust",
        "--no-babel",
        "--spec-version",
        "1.6",
        "-o",
        raw,
    ]


def measure(engine, tool, source, output, source_tool, *, runtime_image=IMAGE):
    if engine == SYFT_RUNTIME_ENGINE:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", runtime_image):
            raise ValueError("runtime experiment requires an inspected immutable local image ID")
    elif runtime_image != IMAGE:
        raise ValueError("legacy resource runtime cannot be overridden")
    output.mkdir(parents=True, exist_ok=False)
    output.chmod(0o700)
    control = output / "controller"
    control.mkdir(mode=0o755)
    control.chmod(0o755)
    if os.geteuid() == 65534:
        raise RuntimeError("host controller must have a different UID from candidate")
    for name in ("ready", "done", "result.json", "go", "ack"):
        (control / name).write_text("pending\n")
    if digest(tool["binary"]) != tool["sha256"]:
        raise ValueError("candidate binary digest mismatch")
    native_elf(tool["binary"])
    mounts = [
        (source, "/source", True),
        (control, "/output", False),
        (Path(__file__).with_name("container_job.py"), "/harness/job.py", True),
    ]
    if engine in SYFT_CONTROL_ENGINES or engine == SYFT_RUNTIME_ENGINE:
        mounts.append((Path(__file__).with_name("syft_control_job.py"), "/harness/syft_control_job.py", True))
    if engine == "cdxgen":
        app = Path(tool["entrypoint"]).parent.parent
        if tree_digest(app) != tool["entrypoint_tree_sha256"]:
            raise ValueError("candidate prepared tree changed")
        mounts.append((app, "/candidate/app", True))
    elif engine != SYFT_RUNTIME_ENGINE:
        mounts.append((Path(tool["binary"]), "/candidate/binary", True))
    invocation = command(engine, source_tool)
    (control / "launch.json").write_text(json.dumps({"command": invocation, "wall_limit_seconds": WALL_SECONDS}) + "\n")
    (control / "heartbeat").touch()
    for marker in control.iterdir():
        marker.chmod(0o644)
    name = "m046-eval-" + uuid.uuid4().hex
    selected_cpus = sorted(os.sched_getaffinity(0))[:2]
    if len(selected_cpus) != 2:
        raise RuntimeError("two native CPU slots required")
    arguments = [
        "run",
        "--platform",
        "linux/" + {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()],
        "--detach",
        "--name",
        name,
        "--network",
        "none",
        "--read-only",
        "--cpus",
        "2",
        "--cpuset-cpus",
        ",".join(map(str, selected_cpus)),
        "--memory",
        str(MEMORY_BYTES),
        "--memory-swap",
        str(MEMORY_BYTES),
        "--pids-limit",
        "256",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "SETUID",
        "--cap-add",
        "SETGID",
        "--cap-add",
        "CHOWN",
        "--cap-add",
        "KILL",
        "--security-opt",
        "no-new-privileges",
        "--init",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=67108864",
        "--tmpfs",
        "/work:rw,noexec,nosuid,nodev,size=268435456,mode=0755",
        "--entrypoint",
        "python3",
    ]
    if engine == SYFT_RUNTIME_ENGINE:
        # Only the trusted controller starts as root. Its existing Popen drops
        # candidate UID/GID/capabilities; the released image defaults to an app user.
        arguments += ["--user", "0:0", "--no-healthcheck"]
    for path, target, readonly in mounts:
        arguments += [
            "--mount",
            f"type=bind,source={path.resolve()},target={target}" + (",readonly" if readonly else ""),
        ]
    arguments += [runtime_image, "/harness/job.py"]
    before = snapshot(source)
    result, paths, baseline, metrics, reason = {}, None, None, None, None
    identifier = None
    started = time.monotonic()
    try:
        identifier = docker(*arguments)
        if not re.fullmatch("[0-9a-f]{64}", identifier):
            raise RuntimeError("Docker did not return a full container identity")
        (output / "container.json").write_text(json.dumps({"id": identifier, "name": name}) + "\n")
        while (control / "ready").read_text().strip() != "ready":
            (control / "heartbeat").touch()
            inspection = json.loads(docker("inspect", identifier))[0]
            if not inspection["State"]["Running"] or time.monotonic() - started > 30:
                raise RuntimeError("benchmark container did not become ready")
            time.sleep(0.05)
        inspection = json.loads(docker("inspect", identifier))[0]
        if inspection["Id"] != identifier:
            raise RuntimeError("Docker inspection identity changed")
        paths = group_paths(inspection["State"]["Pid"])
        enforced = enforcement(paths, inspection["State"]["Pid"], identifier, selected_cpus, MEMORY_BYTES)
        image = json.loads(docker("image", "inspect", inspection["Image"]))[0]
        architecture = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
        if image["Architecture"] != architecture:
            raise RuntimeError("image architecture is not native")
        baseline = counters(paths)
        started = time.monotonic()
        (control / "go").write_text("go\n")
        while True:
            (control / "heartbeat").touch()
            metrics = counters(paths)
            if (control / "done").read_text().strip() == "done":
                result = json.loads((control / "result.json").read_text())
                metrics = counters(paths)
                break
            if metrics["cpu_seconds"] - baseline["cpu_seconds"] > CPU_SECONDS:
                reason = "cpu-budget-exceeded"
                break
            if time.monotonic() - started > WALL_SECONDS + 5:
                reason = "wall-budget-exceeded"
                break
            inspection = json.loads(docker("inspect", identifier))[0]
            if not inspection["State"]["Running"]:
                reason = "container-exited-before-result"
                break
            time.sleep(0.05)
        result.update(
            {
                "aggregate_cpu_seconds": metrics["cpu_seconds"] - baseline["cpu_seconds"],
                "measured_job_wall_seconds": time.monotonic() - started,
                "peak_charged_memory_bytes": metrics["peak_charged_memory_bytes"],
                "cgroup_version": paths["version"],
                "memory_counters": metrics,
                "initial_counters": baseline,
                "enforced_cgroup": enforced,
                "image_id": inspection["Image"],
                "native_architecture": architecture,
                "driver_reason": reason,
                "container_id": identifier,
                "runtime_image": runtime_image,
                "cpu_slots": selected_cpus,
                "command": invocation,
                "memory_measurement": "kernel cgroup charged memory, not aggregate RSS",
                "budget_limits": {
                    "aggregate_cpu_seconds": CPU_SECONDS,
                    "wall_seconds": WALL_SECONDS,
                    "charged_memory_bytes": MEMORY_BYTES,
                },
            }
        )
        exceeded = budget_overruns(result, metrics, baseline)
        result["budget_status"] = "exceeded" if exceeded else "within-measured-bounds"
        result["exceeded_budgets"] = exceeded
        (control / "ack").write_text("ack\n")
    finally:
        # Docker owns the PID namespace; remove it even if the candidate makes
        # another session. The internal heartbeat handles driver SIGKILL too.
        cleanup = subprocess.run([*DOCKER, "rm", "--force", name], capture_output=True, timeout=30)
        if identifier is not None and cleanup.returncode:
            raise RuntimeError("Docker cleanup failed; retained identity requires inspection")
    result["source_unchanged"] = before == snapshot(source)
    raw = control / "raw.json"
    if raw.exists():
        try:
            metadata = raw.lstat()
            content = read_regular(str(raw), None, metadata, 64 * 1024 * 1024)
            result["raw_sha256"] = hashlib.sha256(content).hexdigest()
        except (ValueError, OSError, KeyError, TypeError) as error:
            result["output_error"] = str(error)
    result["measurement_scope"] = (
        "candidate/container controller cgroup; excludes trusted source generation and host snapshot/hash costs"
    )
    result["inventory_output_status"] = "retained-unparsed; correctness requires separate bounded evaluation"
    result["resource_sample_valid"] = (
        result.get("exit_code") == 0
        and result.get("reason") is None
        and result["driver_reason"] is None
        and result["budget_status"] == "within-measured-bounds"
        and result["source_unchanged"]
        and "capture_error" not in result
        and "output_error" not in result
        and "raw_sha256" in result
        and result.get("captured_raw_sha256") == result.get("raw_sha256")
    )
    (output / "measurement.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fixture", action="append", required=True)
    parser.add_argument("--engine", action="append", choices=["syft", "cdxgen", "scalibr"], required=True)
    parser.add_argument("--repeat", type=int, choices=range(1, 4), default=3)
    args = parser.parse_args()
    if platform.machine() not in {"x86_64", "aarch64"}:
        raise ValueError("native architecture required")
    specs = [spec for spec in SPECS if spec["id"] in args.fixture]
    if set(args.fixture) != {spec["id"] for spec in specs}:
        raise ValueError("unknown performance fixture")
    manifest = json.loads(args.manifest.read_text())
    if manifest["architecture"] != {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]:
        raise ValueError("tool manifest architecture differs from native host")
    args.output.mkdir(parents=True, exist_ok=False)
    docker("pull", "--platform", "linux/" + {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()], IMAGE)
    records = []
    for spec in specs:
        source = args.output / "sources" / spec["id"]
        oracle = generate(spec, source)
        for engine in args.engine:
            for repeat in range(args.repeat):
                output = args.output / engine / spec["id"] / str(repeat)
                result = measure(
                    engine, manifest["tools"][engine], source, output, "js" if spec["kind"] == "edges" else "python"
                )
                records.append(
                    {
                        "fixture": spec["id"],
                        "engine": engine,
                        "repeat": repeat,
                        "expected": oracle["expected"],
                        "measurement": result,
                    }
                )
                report = {
                    "status": "exploratory-unreviewed",
                    "architecture": platform.machine(),
                    "benchmark_sha256": digest(__file__),
                    "controller_sha256": digest(Path(__file__).with_name("container_job.py")),
                    "cgroup_reader_sha256": digest(Path(__file__).with_name("cgroup_metrics.py")),
                    "performance_corpus_sha256": digest(Path(__file__).with_name("performance_corpus.py")),
                    "manifest_sha256": digest(args.manifest),
                    "cold_cache_definition": "new container/tmp/cache; host OS page cache not flushed",
                    "budgets": "proposed, not frozen",
                    "records": records,
                }
                (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
                print(
                    f"{spec['id']} {engine} {repeat}: cpu={result['aggregate_cpu_seconds']:.3f}s memory={result['peak_charged_memory_bytes']} reason={result['driver_reason']}",
                    flush=True,
                )


if __name__ == "__main__":
    main()
