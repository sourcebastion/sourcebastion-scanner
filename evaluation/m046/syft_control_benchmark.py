"""Native same-library CPE resource controls; not full extension acceptance."""

import argparse
import json
from pathlib import Path
import platform
import subprocess
import sys

from . import benchmark
from .performance_corpus import SPECS, generate
from .run import digest
from .syft_native import candidate_source_identity


def checkpoint(output, report):
    records = report["records"]
    report["started_attempts"] = len(records)
    report["completed_attempts"] = sum(row["attempt_status"] == "completed" for row in records)
    report["not_started_attempts"] = len(report["plan"]) - len(records)
    temporary = output / ".report.json.tmp"
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(output / "report.json")


def run(binary, manifest_path, output, repeats):
    manifest = json.loads(manifest_path.read_text())
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    identity = candidate_source_identity()
    if (
        manifest["architecture"] != architecture
        or manifest["binary_sha256"] != digest(binary)
        or manifest["candidate_sources"] != identity
    ):
        raise ValueError("control preparation source or binary identity mismatch")
    benchmark.native_elf(binary)
    output.mkdir(parents=True, exist_ok=False)
    tool = {"binary": str(binary), "sha256": manifest["binary_sha256"]}
    records, baseline_failures = [], []
    plan = [
        {"fixture": spec["id"], "engine": engine, "repeat": repeat}
        for spec in SPECS
        if spec["kind"] == "pins"
        for repeat in range(repeats)
        for engine in (list(benchmark.SYFT_CONTROL_ENGINES)[:: -1 if repeat % 2 else 1])
    ]
    report = {
        "status": "preparing",
        "review_status": "unreviewed-native-same-library-cpe-controls-only",
        "architecture": architecture,
        "preparation_manifest_sha256": digest(manifest_path),
        "candidate_sources": identity,
        "binary_sha256": tool["sha256"],
        "runtime_image": benchmark.IMAGE,
        "cold_cache_definition": "new container/tmp/cache; host OS page cache not flushed",
        "budgets": "proposed, not frozen; charged memory is not aggregate RSS",
        "boundary_semantics": "100001 stock-control success does not enforce the frontend occurrence ceiling",
        "limitations": "no extended frontend runtime/resource or production image acceptance; pins only",
        "plan": plan,
        "planned_attempts": len(plan),
        "baseline_failures": baseline_failures,
        "records": records,
    }
    checkpoint(output, report)
    try:
        benchmark.docker("pull", "--platform", "linux/" + architecture, benchmark.IMAGE)
        report["status"] = "running"
        checkpoint(output, report)
        measure_plan(tool, output, repeats, identity, report)
        report["status"] = "completed" if not baseline_failures else "completed-with-baseline-failures"
        checkpoint(output, report)
    except BaseException as error:
        report["status"] = "aborted"
        report["abort_error"] = f"{type(error).__name__}: {error}"[:4096]
        report["abort_policy"] = "no further attempts after infrastructure, source or cleanup uncertainty"
        if records and records[-1]["attempt_status"] != "completed":
            records[-1]["attempt_status"] = "aborted"
        checkpoint(output, report)
        raise
    if baseline_failures:
        raise ValueError("small/medium controls failed exact-output or non-CPE equality gate; all attempts retained")


def measure_plan(tool, output, repeats, identity, report):
    records, baseline_failures = report["records"], report["baseline_failures"]
    for spec in (item for item in SPECS if item["kind"] == "pins"):
        source = output / "sources" / spec["id"]
        oracle = generate(spec, source)
        for repeat in range(repeats):
            pair = []
            # Alternate first arm to reduce a fixed-order shared-page-cache bias.
            engines = list(benchmark.SYFT_CONTROL_ENGINES)
            if repeat % 2:
                engines.reverse()
            for engine in engines:
                if candidate_source_identity() != identity:
                    raise ValueError("evaluation sources changed during comparison")
                directory = output / engine / spec["id"] / str(repeat)
                record = {
                    "fixture": spec["id"],
                    "engine": engine,
                    "repeat": repeat,
                    "expected": oracle["expected"],
                    "attempt_status": "started",
                    "paired_non_cpe_equal": None,
                    "comparative_sample_valid": False,
                }
                records.append(record)
                checkpoint(output, report)
                measurement = benchmark.measure(engine, tool, source, directory, "python")
                record["measurement"] = measurement
                checkpoint(output, report)
                if measurement["resource_sample_valid"]:
                    try:
                        process = subprocess.run(
                            [
                                sys.executable,
                                "-I",
                                "-B",
                                str(Path(__file__).with_name("syft_control_audit.py")),
                                "--raw",
                                str(directory / "controller/raw.json"),
                                "--oracle",
                                str(source.with_suffix(".oracle.json")),
                            ],
                            capture_output=True,
                            timeout=30,
                        )
                        if process.returncode:
                            record["audit_error"] = process.stderr.decode(errors="replace")[:4096]
                        else:
                            record["audit"] = json.loads(process.stdout)
                    except (subprocess.TimeoutExpired, ValueError) as error:
                        record["audit_error"] = str(error)
                record["correct_resource_sample"] = measurement["resource_sample_valid"] and "audit" in record
                if engine.endswith("off") and record.get("audit", {}).get("cpes", 0):
                    record["correct_resource_sample"] = False
                    record["audit_error"] = "CPE-off arm produced CPEs"
                pair.append(record)
                record["attempt_status"] = "completed"
                checkpoint(output, report)
                print(
                    f"{spec['id']} {engine} {repeat}: exit={measurement.get('exit_code')} "
                    f"budget={measurement['budget_status']} exact={record['correct_resource_sample']}",
                    flush=True,
                )
            if candidate_source_identity() != identity or digest(tool["binary"]) != tool["sha256"]:
                for row in pair:
                    row["correct_resource_sample"] = False
                    row["candidate_identity_valid"] = False
                checkpoint(output, report)
                raise ValueError("candidate changed during comparison")
            equal = (
                pair[0]["audit"]["non_cpe_document_sha256"] == pair[1]["audit"]["non_cpe_document_sha256"]
                if all(row["correct_resource_sample"] for row in pair)
                else None
            )
            for row in pair:
                row["paired_non_cpe_equal"] = equal
                row["comparative_sample_valid"] = equal is True
                row["candidate_identity_valid"] = True
            if spec["count"] <= 10000 and equal is not True:
                baseline_failures.append({"fixture": spec["id"], "repeat": repeat})
            checkpoint(output, report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeat", type=int, choices=range(1, 4), default=3)
    args = parser.parse_args()
    run(args.binary.resolve(), args.manifest.resolve(), args.output.resolve(), args.repeat)


if __name__ == "__main__":
    main()
