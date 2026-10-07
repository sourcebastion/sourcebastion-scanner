"""Direct frontend/export synthetic cgroup comparison; no engine acceptance."""

import argparse
import json
from pathlib import Path
import platform
import subprocess
import sys

from . import benchmark
from .direct_prepare import VERSIONS, source_identity
from .performance_corpus import SPECS, generate
from .run import digest, tree_digest
from .syft_control_benchmark import checkpoint


def assert_identity(identity, manifest, records):
    if source_identity() != identity or tree_digest(Path(manifest["app"])) != manifest["app_sha256"]:
        for row in records:
            row.update(
                candidate_identity_valid=False,
                exact_resource_sample=False,
                controlled_refusal=False,
                comparative_sample_valid=False,
            )
        raise ValueError("direct candidate changed")


def runtime_identity(content, manifest, measurement):
    if len(content) > 1024 * 1024:
        raise ValueError("direct runtime metadata too large")
    try:
        runtime = json.loads(content)
    except (ValueError, UnicodeError):
        if (
            measurement.get("exit_code", 0) < 0
            or measurement.get("reason") in {"wall-budget-exceeded", "host-heartbeat-expired"}
            or measurement.get("driver_reason") in {"cpu-budget-exceeded", "wall-budget-exceeded"}
        ):
            return None
        raise ValueError("direct runtime identity unavailable") from None
    if (
        runtime["python"] != "3.14.8"
        or runtime["architecture"] != platform.machine()
        or {key: value["version"] for key, value in runtime["packages"].items()} != VERSIONS
        or runtime["packages"] != manifest["expected_packages"]
    ):
        raise ValueError("direct runtime identity mismatch")
    return runtime


def bounded_audit(raw, oracle, mode):
    try:
        process = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(Path(__file__).with_name("direct_audit.py")),
                "--raw",
                str(raw),
                "--oracle",
                str(oracle),
                "--mode",
                mode,
            ],
            capture_output=True,
            timeout=30,
        )
        if process.returncode:
            return {"audit_error": process.stderr.decode(errors="replace")[:4096]}
        return {"audit": json.loads(process.stdout)}
    except (subprocess.TimeoutExpired, ValueError) as error:
        return {"audit_error": str(error)[:4096]}


def run(manifest_path, output, repeats):
    manifest = json.loads(manifest_path.read_text())
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    identity = source_identity()
    if (
        manifest["architecture"] != architecture
        or manifest["candidate_sources"] != identity
        or manifest["python_version"] != "3.14.8"
        or tree_digest(Path(manifest["app"])) != manifest["app_sha256"]
    ):
        raise ValueError("direct preparation identity mismatch")
    output.mkdir(parents=True, exist_ok=False)
    specs = [row for row in SPECS if row["kind"] == "pins"]
    plan = [
        {"fixture": spec["id"], "repeat": repeat, "engine": mode}
        for spec in specs
        for repeat in range(repeats)
        for mode in sorted(benchmark.DIRECT_ENGINES)[:: -1 if repeat % 2 else 1]
    ]
    records, failures = [], []
    report = {
        "status": "preparing",
        "architecture": architecture,
        "candidate_sources": identity,
        "preparation_sha256": digest(manifest_path),
        "prepared_tree_sha256": manifest["app_sha256"],
        "runtime_image": benchmark.IMAGE,
        "plan": plan,
        "records": records,
        "baseline_failures": failures,
        "budgets": "proposed, not frozen; cgroup charged memory, not aggregate RSS",
        "scope": "direct Python inventory and inventory-plus-CDX serialization/validation; synthetic pins only",
        "limits": "no Grype, complete process trace, non-Python, Alpine image, licenses or engine acceptance",
        "boundary_semantics": "100k structural cap is not guaranteed complete capacity; node/byte/CPU/memory limits may refuse earlier",
        "cold_cache_definition": "new container/tmp; host OS page cache not flushed",
    }
    checkpoint(output, report)
    try:
        benchmark.docker("pull", "--platform", "linux/" + architecture, benchmark.IMAGE)
        report["status"] = "running"
        checkpoint(output, report)
        for spec in specs:
            source = output / "sources" / spec["id"]
            generate(spec, source)
            for repeat in range(repeats):
                pair = []
                for mode in sorted(benchmark.DIRECT_ENGINES)[:: -1 if repeat % 2 else 1]:
                    assert_identity(identity, manifest, records)
                    row = {"fixture": spec["id"], "engine": mode, "repeat": repeat, "attempt_status": "started"}
                    records.append(row)
                    checkpoint(output, report)
                    directory = output / mode / spec["id"] / str(repeat)
                    measurement = benchmark.measure(mode, manifest, source, directory, "python")
                    row["measurement"] = measurement
                    checkpoint(output, report)
                    assert_identity(identity, manifest, records)
                    stdout_path = directory / "controller/stdout.log"
                    if stdout_path.stat().st_size > 1024 * 1024:
                        raise ValueError("direct runtime metadata too large")
                    runtime = runtime_identity(stdout_path.read_bytes(), manifest, measurement)
                    row["runtime"] = runtime
                    row["runtime_identity_valid"] = runtime is not None
                    row["candidate_identity_valid"] = True
                    raw = directory / "controller/raw.json"
                    if raw.is_file():
                        row.update(bounded_audit(raw, source.with_suffix(".oracle.json"), mode))
                    valid_execution = (
                        measurement["budget_status"] == "within-measured-bounds"
                        and row["runtime_identity_valid"]
                        and measurement["source_unchanged"]
                        and measurement.get("reason") is None
                        and measurement["driver_reason"] is None
                        and "capture_error" not in measurement
                        and measurement.get("raw_sha256") == measurement.get("captured_raw_sha256")
                        and "raw_sha256" in measurement
                    )
                    disposition = row.get("audit", {}).get("status")
                    row["exact_resource_sample"] = (
                        measurement["resource_sample_valid"]
                        and row["runtime_identity_valid"]
                        and disposition == "exact-synthetic-pin-identities-and-roots"
                    )
                    row["controlled_refusal"] = (
                        valid_execution and measurement.get("exit_code") == 2 and disposition == "controlled-refusal"
                    )
                    if spec["count"] <= 10000 and not row["exact_resource_sample"]:
                        failures.append({"fixture": spec["id"], "engine": mode, "repeat": repeat})
                    row["attempt_status"] = "completed"
                    pair.append(row)
                    checkpoint(output, report)
                    print(
                        f"{spec['id']} {mode} {repeat}: exact={row['exact_resource_sample']} refusal={row['controlled_refusal']}",
                        flush=True,
                    )
                equal = (
                    pair[0]["audit"]["canonical_inventory_sha256"] == pair[1]["audit"]["canonical_inventory_sha256"]
                    if all(row["exact_resource_sample"] for row in pair)
                    else None
                )
                for row in pair:
                    row["paired_canonical_inventory_equal"] = equal
                    row["comparative_sample_valid"] = equal is True
                if equal is False:
                    failures.append(
                        {"fixture": spec["id"], "repeat": repeat, "reason": "paired canonical inventory differs"}
                    )
                checkpoint(output, report)
        assert_identity(identity, manifest, records)
        report["status"] = "completed" if not failures else "completed-with-baseline-failures"
        checkpoint(output, report)
    except BaseException as error:
        report["status"] = "aborted"
        report["abort_error"] = f"{type(error).__name__}: {error}"[:4096]
        if records and records[-1]["attempt_status"] != "completed":
            records[-1]["attempt_status"] = "aborted"
        checkpoint(output, report)
        raise
    if failures:
        raise ValueError("small/medium direct candidate failed; all attempts retained")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repeat", type=int, choices=range(1, 4), default=3)
    args = parser.parse_args()
    run(args.manifest.resolve(), args.output.resolve(), args.repeat)


if __name__ == "__main__":
    main()
