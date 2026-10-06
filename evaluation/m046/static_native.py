"""Native traced static frontend evaluation against built-in synthetic fixtures.

This is correctness/trace evidence, not aggregate resource or engine acceptance.
The reviewed evaluation namespaces expose host reads; they are not a jail.
"""

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path, PurePosixPath
import platform
import re
import sys

from .benchmark import native_elf
from .corpus import CORPUS
from .run import MAX_OUTPUT, compare, digest, execute, materialize, snapshot

NETWORK_SYSCALLS = {
    "socket",
    "socketcall",
    "socketpair",
    "connect",
    "accept",
    "accept4",
    "bind",
    "listen",
    "getsockname",
    "getpeername",
    "sendto",
    "sendmsg",
    "sendmmsg",
    "recvfrom",
    "recvmsg",
    "recvmmsg",
    "shutdown",
    "setsockopt",
    "getsockopt",
}
SUPPORTED_MANIFESTS = {
    "python-pyproject",
    "python-pyproject-optional",
    "python-setup-cfg",
    "python-static-setup",
}


def trace_admission(trace, interpreter):
    invocations = re.findall(r"^\s*(?:\d+\s+|\[pid\s+\d+\]\s+)?([a-z][a-z0-9_]*)\((.*)$", trace, re.MULTILINE)
    calls = [name for name, _arguments in invocations]
    executions = []
    for name, arguments in invocations:
        if name == "execve":
            try:
                filename, _end = json.JSONDecoder().raw_decode(arguments)
            except ValueError:
                raise ValueError("static-native-process-or-network-attempt") from None
            executions.append(filename)
    network = [name for name in calls if name in NETWORK_SYSCALLS]
    if (
        executions != [interpreter]
        or "execveat" in calls
        or network
        or any(name in {"fork", "vfork", "clone", "clone3"} for name in calls)
    ):
        raise ValueError("static-native-process-or-network-attempt")
    return executions, len(network)


def supported(fixture):
    return (
        fixture["ecosystem"] == "python"
        and bool(fixture["files"])
        and all(PurePosixPath(path).suffix in {".in", ".txt", ".pip"} for path in fixture["files"])
        and not fixture["symlinks"]
    )


def runtime_identity():
    if platform.python_version() != "3.14.8" or importlib.metadata.version("packaging") != "25.0":
        raise ValueError("static-native-runtime-pin-mismatch")
    native_elf(Path(sys.executable).resolve())
    distribution = importlib.metadata.distribution("packaging")
    files = {}
    for path in distribution.files or ():
        if path.suffix == ".py" and path.parts[0] == "packaging":
            files[path.as_posix()] = digest(distribution.locate_file(path))
    if not files:
        raise ValueError("static-native-runtime-manifest-empty")
    return {
        "python": platform.python_version(),
        "architecture": platform.machine(),
        "python_binary_sha256": digest(Path(sys.executable).resolve()),
        "packaging": distribution.version,
        "packaging_source_files": files,
    }


def source_identity():
    directory = Path(__file__).resolve().parent
    files = {path.name: digest(path) for path in sorted(directory.glob("*.py"))}
    files["requirements-static.txt"] = digest(directory / "requirements-static.txt")
    return {
        "modules": files,
        "corpus_data_sha256": hashlib.sha256(json.dumps(CORPUS, sort_keys=True).encode()).hexdigest(),
    }


def run(output, strace):
    identity = runtime_identity()
    identity["tracer_binary_sha256"] = digest(strace)
    source_before = source_identity()
    output.mkdir(parents=True, exist_ok=False)
    script = Path(__file__).with_name("static_cli.py").resolve()
    records = []
    for fixture in CORPUS:
        directory = output / fixture["id"]
        directory.mkdir()
        source, scratch = directory / "source", directory / "work"
        scratch.mkdir()
        materialize(fixture, source)
        before = snapshot(source)
        if source_identity() != source_before:
            raise ValueError("static-native-controller-source-changed")
        result = execute(source, scratch, strace, [sys.executable, "-I", "-B", str(script), "--root", str(source)], 45)
        raw = scratch / "stdout.log"
        if raw.stat().st_size > MAX_OUTPUT:
            raise ValueError("static-native-output-overflow")
        content = raw.read_bytes()
        if len(content) > MAX_OUTPUT:
            raise ValueError("static-native-output-overflow")
        observed = json.loads(content)
        trace = (scratch / "trace.log").read_text()
        executions, network_attempts = trace_admission(trace, sys.executable)
        differences = compare(fixture["expected"], observed)
        source_unchanged = snapshot(source) == before
        expected_exit = 2 if observed["inventory_status"] == "failed" else 0
        if result["timed_out"] or result["exit_code"] != expected_exit or not source_unchanged:
            raise ValueError("static-native-invocation-invalid")
        if source_identity() != source_before:
            raise ValueError("static-native-controller-source-changed")
        admitted = supported(fixture) or fixture["id"] in SUPPORTED_MANIFESTS
        if admitted and not differences["full_contract_agreement"]:
            raise ValueError("static-native-supported-oracle-mismatch")
        record = {
            "fixture": fixture["id"],
            "supported_pip_contract": supported(fixture),
            "supported_static_contract": admitted,
            "resource_acceptance": "not-assessed",
            "result": result,
            "raw_sha256": hashlib.sha256(content).hexdigest(),
            "trace_sha256": digest(scratch / "trace.log"),
            "source_unchanged": source_unchanged,
            "executions": executions,
            "network_attempts": network_attempts,
            "comparison": differences,
        }
        (directory / "record.json").write_text(json.dumps(record, indent=2) + "\n")
        records.append(record)
    summary = {
        "status": "evaluation-only",
        "runtime": identity,
        "controller_source_before": source_before,
        "controller_source_after": source_identity(),
        "supported_pip_cases": sum(record["supported_pip_contract"] for record in records),
        "supported_static_cases": sum(record["supported_static_contract"] for record in records),
        "total_cases": len(records),
        "records": records,
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--strace", required=True, type=Path)
    args = parser.parse_args()
    run(args.output.resolve(), args.strace.resolve())


if __name__ == "__main__":
    main()
