"""Linux-only, synthetic-corpus evaluator. Never call this on customer sources.

No production modules are imported. Outputs, traces and caches stay outside the
read-only fixture. Network and PID namespaces are required, never optional.
"""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import sys
import time
from urllib.parse import unquote

if __package__:
    from .corpus import CORPUS, VERSION
    from .oracle import DIMENSIONS
else:
    from corpus import CORPUS, VERSION
    from oracle import DIMENSIONS


MAX_FILE = 2 * 1024 * 1024
MAX_OUTPUT = 64 * 1024 * 1024
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9,._-]+\])?==([A-Za-z0-9][A-Za-z0-9.!+_-]*)$")


def digest(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def validate_case(fixture):
    paths = set(fixture["files"]) | set(fixture["symlinks"])
    if len(paths) != len(fixture["files"]) + len(fixture["symlinks"]):
        raise ValueError("overlapping files and links")
    for path in paths:
        p = Path(path)
        if p.is_absolute() or ".." in p.parts or not p.parts:
            raise ValueError("unsafe fixture path")
    for content in fixture["files"].values():
        if len(content.encode()) > MAX_FILE:
            raise ValueError("fixture file exceeds budget")
    for target in fixture["symlinks"].values():
        # Escapes are intentional test data, restricted to our synthetic sibling.
        if target not in {"../outside.txt", "a", "b"}:
            raise ValueError("unapproved synthetic symlink")
    expected = fixture["expected"]
    identities = set(expected["packages"])
    if len(identities) != len(expected["packages"]):
        raise ValueError("duplicate expected identity")
    for parent, child in expected["edges"]:
        if parent not in identities or child not in identities:
            raise ValueError("edge endpoint absent from oracle")
    if set(paths) != {record["path"] for record in expected["inputs"]}:
        raise ValueError("per-input oracle does not cover fixture paths")
    if identities != {record["package"] for record in expected["occurrences"]}:
        raise ValueError("occurrences do not cover expected identities")
    for record in expected["occurrences"]:
        if record["path"] not in fixture["files"] or record["root"] not in expected["roots"]:
            raise ValueError("occurrence source/root absent from oracle")
    for record in expected["relationships"]:
        for endpoint in (record["parent"], record["child"]):
            if not any(
                occurrence["package"] == endpoint and occurrence["root"] == record["root"]
                for occurrence in expected["occurrences"]
            ):
                raise ValueError("relationship has no occurrence in its root")


def materialize(fixture, destination):
    validate_case(fixture)
    destination.mkdir(parents=True, exist_ok=False)
    (destination.parent / "outside.txt").write_text("m046-outside-sentinel==99.99.99\n")
    for name, content in fixture["files"].items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    for name, target in fixture["symlinks"].items():
        link = destination / name
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target)


def snapshot(root):
    result = {}
    for path in sorted(root.rglob("*")):
        name = str(path.relative_to(root))
        if path.is_symlink():
            result[name] = {"symlink": os.readlink(path)}
        elif path.is_file():
            result[name] = {"sha256": digest(path), "mode": path.stat().st_mode & 0o777}
        elif path.is_dir():
            result[name] = {"directory": True}
    return result


def tree_digest(root):
    return hashlib.sha256(json.dumps(snapshot(root), sort_keys=True).encode()).hexdigest()


def projection(root):
    """Narrow Syft extension experiment; not a general discovery registry.

    Only complete, exact-pin-only .in/.txt documents qualify. Includes, ranges,
    markers, constraints and free prose are deliberately left unprojected. The
    emitted mapping is experimental provenance, not production location data.
    """
    mappings = []
    paths = sorted(root.rglob("*"))
    # A constrained lock's pins do not independently install packages. This
    # probe refuses whole inputs with include/constraint directives rather than
    # guessing root reachability; the full S02/S03 adapter must model them.
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.suffix not in {".in", ".txt"}:
            continue
        if path.stat().st_size <= MAX_FILE and re.search(
            r"(?m)^\s*(?:-[rc](?:\s|[^-])|--(?:requirement|constraint)(?:\s|=))", path.read_text()
        ):
            return []
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.suffix not in {".in", ".txt"}:
            continue
        if path.name == "requirements.txt":
            continue
        if path.stat().st_size > MAX_FILE:
            continue
        lines = path.read_text().replace("\\\n", " ").splitlines()
        pins = []
        for line in lines:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            line = re.sub(r"\s+--hash=sha256:[a-fA-F0-9]{64}(?=\s|$)", "", line).strip()
            if not PIN.fullmatch(line):
                break
            pins.append(line)
        else:
            if pins:
                original = str(path.relative_to(root))
                projected = (
                    Path(".m046-projection") / hashlib.sha256(original.encode()).hexdigest() / "requirements.txt"
                )
                target = root / projected
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("\n".join(pins) + "\n")
                mappings.append({"original": original, "projected": str(projected), "sha256": digest(path)})
    return mappings


def identity(purl):
    """Comparison key retains ecosystem, namespace and case except PEP 503."""
    if not purl or not purl.startswith("pkg:") or "@" not in purl:
        return None
    base = purl[4:].split("?", 1)[0].split("#", 1)[0]
    ecosystem, package = base.split("/", 1)
    name, version = package.rsplit("@", 1)
    name, version = unquote(name), unquote(version)
    if ecosystem == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    if not version:
        return None
    return f"{ecosystem}:{name}@{version}"


def normalize(document, kind):
    if not isinstance(document, dict):
        raise ValueError("inventory output must be a JSON object")
    packages = set()
    applications = set()
    edges = set()
    refs = {}
    locations = {}
    if kind.startswith("syft"):
        for package in document.get("artifacts", []):
            key = identity(package.get("purl"))
            if key:
                packages.add(key)
                refs[package["id"]] = key
                locations.setdefault(key, set()).update(location["path"] for location in package.get("locations", []))
        for edge in document.get("artifactRelationships", []):
            if edge["type"] == "dependency-of" and edge["parent"] in refs and edge["child"] in refs:
                # Syft dependency-of points from dependency to dependent.
                edges.add((refs[edge["child"]], refs[edge["parent"]]))
    else:

        def collect(components, metadata_root=False):
            for package in components:
                key = identity(package.get("purl"))
                if key:
                    # Explicit component role/structure, independent of oracle
                    # membership. Application components are never external
                    # libraries merely because an exporter moves their record.
                    if metadata_root or package.get("type") == "application":
                        applications.add(key)
                    else:
                        packages.add(key)
                        refs[package.get("bom-ref", package.get("purl"))] = key
                collect(package.get("components", []))

        component = document.get("metadata", {}).get("component")
        if component:
            collect([component], metadata_root=True)
        collect(document.get("components", []))
        for dependency in document.get("dependencies", []):
            parent = refs.get(dependency["ref"])
            for child_ref in dependency.get("dependsOn", []):
                child = refs.get(child_ref)
                if parent and child:
                    edges.add((parent, child))
    return {
        "packages": sorted(packages),
        "edges": [list(edge) for edge in sorted(edges)],
        "locations": {key: sorted(paths) for key, paths in sorted(locations.items())},
        "application_identities": sorted(applications),
        # Exporter JSON does not imply source roots/scopes/input outcomes. The
        # substantive adapter must emit the independently compared dimensions.
        "semantic_dimensions": {dimension: None for dimension in DIMENSIONS},
        "coverage": "unassessed",
    }


def compare(expected, observed):
    packages = set(observed["packages"])
    edges = set(map(tuple, observed["edges"]))
    result = {
        "missing_packages": sorted(set(expected["packages"]) - packages),
        "extra_packages": sorted(packages - set(expected["packages"])),
        "missing_edges": sorted(set(map(tuple, expected["edges"])) - edges),
        "extra_edges": sorted(edges - set(map(tuple, expected["edges"]))),
        "coverage": "unassessed",  # Never infer coverage from empty inventory or exit 0.
        "declarations": "unassessed",
    }
    expected_applications = {record["identity"] for record in expected.get("applications", [])}
    observed_applications = set(observed.get("application_identities", []))
    result["missing_applications"] = sorted(expected_applications - observed_applications)
    result["extra_applications"] = sorted(observed_applications - expected_applications)
    result["semantic_dimensions"] = {}
    for dimension in DIMENSIONS:
        wanted = expected.get(dimension)
        actual = observed.get("semantic_dimensions", {}).get(dimension)
        if wanted is None or actual is None:
            result["semantic_dimensions"][dimension] = {"status": "unreported", "agreement": False}
            continue
        if dimension == "fidelity":
            result["semantic_dimensions"][dimension] = {
                "status": "compared",
                "agreement": wanted == actual,
                "expected": wanted,
                "observed": actual,
            }
        else:
            # Preserve multiplicity. Identity sets cannot detect lost duplicate
            # occurrences, multiple roots or overlapping environment records.
            from collections import Counter

            canonical = lambda values: Counter(
                json.dumps(value, sort_keys=True, separators=(",", ":")) for value in values
            )
            missing = list((canonical(wanted) - canonical(actual)).elements())
            extra = list((canonical(actual) - canonical(wanted)).elements())
            result["semantic_dimensions"][dimension] = {
                "status": "compared",
                "agreement": not missing and not extra,
                "missing": [json.loads(value) for value in sorted(missing)],
                "extra": [json.loads(value) for value in sorted(extra)],
            }
    result["full_contract_agreement"] = not any(
        result[key]
        for key in (
            "missing_packages",
            "extra_packages",
            "missing_edges",
            "extra_edges",
            "missing_applications",
            "extra_applications",
        )
    ) and all(record["agreement"] for record in result["semantic_dimensions"].values())
    return result


def sandbox(source, scratch, tracer, command):
    # Called only inside an isolated network/user/mount/PID namespace.
    subprocess.run(["/bin/mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["/bin/mount", "--bind", str(source), str(source)], check=True)
    subprocess.run(["/bin/mount", "-o", "remount,bind,ro,noexec,nosuid,nodev", str(source)], check=True)
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT, MAX_OUTPUT))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    cpus = sorted(os.sched_getaffinity(0))[:2]
    os.sched_setaffinity(0, cpus)
    os.chdir(source)
    env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "TZ": "UTC",
        "NO_COLOR": "1",
        "XDG_CACHE_HOME": str(scratch / "cache"),
        "TMPDIR": str(scratch / "temp"),
        "SYFT_CHECK_FOR_APP_UPDATE": "false",
        "SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true",
        "CDXGEN_NO_PROGRESS": "true",
        "CDXGEN_TIMEOUT_MS": "30000",
        "CDXGEN_PYPI_METADATA": "false",
        "FETCH_LICENSE": "false",
    }
    (scratch / "temp").mkdir()
    os.execve(
        str(tracer),
        [
            str(tracer),
            "-f",
            "-qq",
            "-s",
            "4096",
            "-e",
            "trace=process,network,%file",
            "-o",
            str(scratch / "trace.log"),
            *command,
        ],
        env,
    )


def execute(source, scratch, tracer, command, timeout):
    script = str(Path(__file__).resolve())
    invocation = [
        sys.executable,
        script,
        "_guard",
        str(os.getpid()),
        "unshare",
        "-Urnmpf",
        "--kill-child=KILL",
        sys.executable,
        script,
        "_sandbox",
        str(source),
        str(scratch),
        str(tracer),
        *command,
    ]
    started = time.monotonic()
    timed_out = False
    with (scratch / "stdout.log").open("wb") as stdout, (scratch / "stderr.log").open("wb") as stderr:
        process = subprocess.Popen(
            invocation,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
        while True:
            pid, status, usage = os.wait4(process.pid, os.WNOHANG)
            if pid:
                process.returncode = os.waitstatus_to_exitcode(status)
                break
            if time.monotonic() - started > timeout:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                _, status, usage = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
                break
            time.sleep(0.05)
    return {
        "exit_code": process.returncode,
        "timed_out": timed_out,
        "wall_seconds": round(time.monotonic() - started, 3),
        "cpu_seconds": round(usage.ru_utime + usage.ru_stime, 3),
        "max_child_rss_kib": usage.ru_maxrss,
    }


def guard(supervisor_pid, invocation):
    """Kill the dedicated job group on supervisor death, including SIGKILL.

    This guardian stays outside the new user/PID namespaces, so credential
    transitions in unshare cannot clear its parent-death signal. No candidate
    starts until the signal and race-closing parent check are both installed.
    """
    if os.getpid() != os.getpgrp() or os.getpid() != os.getsid(0):
        raise RuntimeError("guardian requires a dedicated session")

    def cancel(_signum, _frame):
        os.killpg(os.getpgrp(), signal.SIGKILL)

    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)
    signal.signal(signal.SIGHUP, cancel)
    # Masks survive exec. A worker's blocked signals must not leave the
    # kernel's parent-death SIGTERM pending forever.
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    libc = ctypes.CDLL(None, use_errno=True)
    # Linux PR_SET_PDEATHSIG. Failure is fatal; containment is never optional.
    if libc.prctl(1, int(signal.SIGTERM), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_PDEATHSIG")
    if os.getppid() != supervisor_pid:
        cancel(None, None)
    child = subprocess.Popen(invocation)
    status = child.wait()
    # Reproduce child signal termination rather than obscuring it as exit 137.
    if status < 0:
        signal.signal(-status, signal.SIG_DFL)
        os.kill(os.getpid(), -status)
    raise SystemExit(status)


def run_contained(command):
    """Contain orchestrator children as well as each isolated candidate job."""
    process = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "_guard", str(os.getpid()), *command],
        start_new_session=True,
    )
    try:
        status = process.wait()
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise
    if status:
        raise subprocess.CalledProcessError(status, command)


def run(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    binary = args.binary.resolve(strict=True)
    tracer = args.strace.resolve(strict=True)
    if digest(binary) != args.sha256:
        raise ValueError("candidate SHA256 mismatch")
    entrypoint = args.entrypoint.resolve(strict=True) if args.entrypoint else None
    if entrypoint and (args.engine != "cdxgen" or digest(entrypoint) != args.entrypoint_sha256):
        raise ValueError("entrypoint SHA256 mismatch or unsupported engine")
    prepared_tree = entrypoint.parent.parent if entrypoint else None
    if prepared_tree and tree_digest(prepared_tree) != args.entrypoint_tree_sha256:
        raise ValueError("prepared entrypoint tree SHA256 mismatch")
    corpus_hash = digest(Path(__file__).with_name("corpus.py"))
    oracle_hash = digest(Path(__file__).with_name("oracle.py"))
    corpus_data_hash = hashlib.sha256(json.dumps(CORPUS, sort_keys=True).encode()).hexdigest()
    runner_hash = digest(Path(__file__))
    records = []
    selected = [fixture for fixture in CORPUS if not args.fixture or fixture["id"] in args.fixture]
    if not selected or (args.fixture and set(args.fixture) != {fixture["id"] for fixture in selected}):
        raise ValueError("unknown fixture")
    for fixture in selected:
        for repetition in range(args.repeat):
            directory = output / fixture["id"] / str(repetition)
            directory.mkdir(parents=True)
            source, scratch = directory / "source", directory / "run"
            materialize(fixture, source)
            scratch.mkdir()
            mappings = projection(source) if args.engine == "syft-projection" else []
            before = snapshot(source)
            raw = scratch / "raw.json"
            if args.engine.startswith("syft"):
                command = [
                    str(binary),
                    "scan",
                    f"dir:{source}",
                    "--base-path",
                    str(source),
                    "--parallelism",
                    "2",
                    "-o",
                    f"syft-json={raw}",
                ]
            elif args.engine == "cdxgen":
                types = {
                    "python": "python",
                    "node": "js",
                    "go": "go",
                    "rust": "rust",
                    "java": "java",
                    "dotnet": "dotnet",
                    "ruby": "ruby",
                    "php": "php",
                }
                command = [
                    str(binary),
                    *([str(entrypoint)] if entrypoint else []),
                    str(source),
                    "-t",
                    types[fixture["ecosystem"]],
                    "--no-install-deps",
                    "--no-cache",
                    "--no-progress",
                    "--no-introspect",
                    "--no-rust",
                    "--no-babel",
                    "--spec-version",
                    "1.6",
                    "-o",
                    str(raw),
                ]
            else:
                command = [
                    str(binary),
                    "--root",
                    str(source),
                    "--offline",
                    "--plugins",
                    "python,java,javascript,go,rust,dotnet,ruby,php",
                    "--max-file-size",
                    str(MAX_FILE),
                    "--deterministic-ids",
                    "-o",
                    f"cdx-json={raw}",
                ]
            metrics = execute(source, scratch, tracer, command, args.timeout)
            record = {
                "fixture": fixture["id"],
                "repetition": repetition,
                "command": command,
                "metrics": metrics,
                "source_unchanged": before == snapshot(source),
                "projection": mappings,
                "expected": fixture["expected"],
            }
            try:
                document = json.loads(raw.read_text())
                record["observed"] = normalize(document, args.engine)
                record["comparison"] = compare(fixture["expected"], record["observed"])
                record["raw_sha256"] = digest(raw)
            except (OSError, ValueError, KeyError, TypeError) as error:
                record["output_error"] = str(error)
            trace = scratch / "trace.log"
            if trace.exists():
                trace_text = trace.read_text(errors="replace")
                record["trace_sha256"] = digest(trace)
                record["exec_observations"] = [
                    line for line in trace_text.splitlines() if "execve(" in line or "execveat(" in line
                ]
                record["network_observations"] = [
                    line for line in trace_text.splitlines() if "connect(" in line or "sendto(" in line
                ]
                record["audit_status"] = "manual-review-required"
            records.append(record)
            (output / "report.json").write_text(
                json.dumps(
                    {
                        "corpus": VERSION,
                        "corpus_sha256": corpus_hash,
                        "oracle_sha256": oracle_hash,
                        "corpus_data_sha256": corpus_data_hash,
                        "runner_sha256": runner_hash,
                        "engine": args.engine,
                        "binary_sha256": args.sha256,
                        "tracer_sha256": digest(tracer),
                        "platform": sys.platform,
                        "entrypoint_sha256": args.entrypoint_sha256,
                        "entrypoint_tree_sha256": args.entrypoint_tree_sha256,
                        "architecture": os.uname().machine,
                        "sandbox": "network+user+mount+PID namespaces; source ro,noexec; scrubbed environment",
                        "records": records,
                    },
                    indent=2,
                )
                + "\n"
            )
            print(
                f"{args.engine} {fixture['id']} {repetition}: exit={metrics['exit_code']} wall={metrics['wall_seconds']}s",
                flush=True,
            )
    report_path = output / "report.json"
    report = json.loads(report_path.read_text())
    report["complete"] = True
    report["prepared_tree_unchanged"] = (
        tree_digest(prepared_tree) == args.entrypoint_tree_sha256 if prepared_tree else None
    )
    report_path.write_text(json.dumps(report, indent=2) + "\n")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "_guard":
        guard(int(sys.argv[2]), sys.argv[3:])
        return
    if len(sys.argv) > 1 and sys.argv[1] == "_sandbox":
        sandbox(*(Path(value) for value in sys.argv[2:5]), sys.argv[5:])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=["syft", "syft-projection", "cdxgen", "scalibr"], required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument(
        "--entrypoint", type=Path, help="Prepared cdxgen JS entrypoint; binary is its bundled Node runtime"
    )
    parser.add_argument("--entrypoint-sha256")
    parser.add_argument(
        "--entrypoint-tree-sha256", help="Digest of prepared cdxgen app snapshot, including its bundled modules"
    )
    parser.add_argument("--strace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fixture", action="append")
    parser.add_argument("--repeat", type=int, default=2, choices=range(1, 4))
    parser.add_argument("--timeout", type=int, default=45, choices=range(1, 301))
    run(parser.parse_args())


if __name__ == "__main__":
    main()
