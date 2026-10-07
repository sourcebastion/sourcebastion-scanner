"""Finite restricted-provider diagnostic, not a selected production pipeline."""

import argparse
import json
import os
import signal
from pathlib import Path
import platform
import subprocess
import sys

from .provider_corpus import PROVIDER_CORPUS
from .run import digest, execute, materialize, snapshot, MAX_OUTPUT
from .syft_control_benchmark import checkpoint
from .syft_native import candidate_source_identity, identity, native_elf, trace_admission


def audit_child(command, stdout, stderr):
    """Guardian closes supervisor-death race; timeout kills its whole session."""
    process = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            "import sys; sys.path.insert(0, sys.argv[1]); from run import guard; "
            "guard(int(sys.argv[2]), sys.argv[3:])",
            str(Path(__file__).resolve().parent),
            str(os.getpid()),
            *command,
        ],
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    try:
        return process.wait(timeout=30)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise


def run(binary, manifest_path, tracer, output):
    native_elf(binary)
    initial = identity(binary)
    manifest = json.loads(manifest_path.read_text())
    if (
        manifest["binary_sha256"] != initial["binary_sha256"]
        or manifest["candidate_sources"] != candidate_source_identity()
    ):
        raise ValueError("provider-preparation-identity-mismatch")
    output.mkdir(parents=True, exist_ok=False)
    records = []
    report = {
        "status": "running",
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "candidate_sources": initial,
        "preparation_sha256": digest(manifest_path),
        "tracer_sha256": digest(tracer),
        "planned_attempts": len(PROVIDER_CORPUS) * 2,
        "plan": [{"fixture": row["id"], "repeat": repeat} for row in PROVIDER_CORPUS for repeat in range(2)],
        "records": records,
        "scope": "restricted provider raw facts, baseline identities/edges and explicit unreported axes only",
        "limits": "no canonical hybrid join/export, aggregate cgroup resource, Alpine/license or engine acceptance",
    }
    checkpoint(output, report)
    try:
        for fixture in PROVIDER_CORPUS:
            directory = output / fixture["id"]
            directory.mkdir()
            source = directory / "source"
            materialize(fixture, source)
            before = snapshot(source)
            (directory / "source-snapshot.json").write_text(json.dumps(before, sort_keys=True) + "\n")
            normalized = []
            for repeat in range(2):
                if (
                    identity(binary) != initial
                    or digest(manifest_path) != report["preparation_sha256"]
                    or digest(tracer) != report["tracer_sha256"]
                ):
                    raise ValueError("provider-source-or-binary-changed")
                scratch = directory / str(repeat)
                scratch.mkdir()
                record = {"fixture": fixture["id"], "repeat": repeat, "attempt_status": "started"}
                records.append(record)
                checkpoint(output, report)
                result = execute(
                    source,
                    scratch,
                    tracer,
                    [
                        str(binary),
                        "--root",
                        str(source),
                        "--mode",
                        "provider",
                        "--generate-cpes=false",
                        "--timeout=40s",
                    ],
                    45,
                )
                record["result"] = result
                record["source_unchanged"] = snapshot(source) == before
                if (
                    not record["source_unchanged"]
                    or identity(binary) != initial
                    or digest(tracer) != report["tracer_sha256"]
                ):
                    raise ValueError("provider-source-or-candidate-changed-during-attempt")
                raw, trace = scratch / "stdout.log", scratch / "trace.log"
                record["raw_sha256"] = digest(raw)
                if raw.stat().st_size > MAX_OUTPUT:
                    raise ValueError("provider-output-budget-exceeded")
                if trace.is_file():
                    record["trace_sha256"] = digest(trace)
                    if trace.stat().st_size > MAX_OUTPUT:
                        raise ValueError("provider-trace-budget-exceeded")
                    try:
                        record["trace"] = trace_admission(trace.read_text(), binary, require_complete=True)
                        record["complete_process_network_admission"] = True
                    except ValueError as error:
                        record["complete_process_network_admission"] = False
                        record["trace_refusal"] = str(error)
                else:
                    record["complete_process_network_admission"] = False
                    record["trace_refusal"] = "missing-provider-trace"
                if result["exit_code"] == 0 and not result["timed_out"]:
                    try:
                        with (
                            (scratch / "audit.json").open("wb") as stdout,
                            (scratch / "audit.stderr").open("wb") as stderr,
                        ):
                            audited = audit_child(
                                [
                                    sys.executable,
                                    "-I",
                                    "-B",
                                    str(Path(__file__).with_name("provider_audit.py")),
                                    "--raw",
                                    str(raw),
                                    "--fixture",
                                    fixture["id"],
                                    "--facts-output",
                                    str(scratch / "facts.json"),
                                    "--source-snapshot",
                                    str(directory / "source-snapshot.json"),
                                ],
                                stdout=stdout,
                                stderr=stderr,
                            )
                        if audited != 0 or (scratch / "audit.json").stat().st_size > 1024 * 1024:
                            record["audit_status"] = "refused"
                        else:
                            audited_json = json.loads((scratch / "audit.json").read_text())
                            record["audit_status"] = "facts-retained-not-qualified"
                            record["comparison"] = audited_json["comparison"]
                            record["audit_sha256"] = digest(scratch / "audit.json")
                            facts_path = scratch / "facts.json"
                            if (
                                facts_path.stat().st_size > MAX_OUTPUT
                                or digest(facts_path) != audited_json["facts_sha256"]
                            ):
                                raise ValueError("provider-audit-facts-identity-mismatch")
                            record["facts_sha256"] = audited_json["facts_sha256"]
                            normalized.append(audited_json["facts_sha256"])
                    except subprocess.TimeoutExpired:
                        record["audit_status"] = "audit-timeout-invalid"
                else:
                    record["audit_status"] = "execution-invalid"
                record["attempt_status"] = "completed"
                checkpoint(output, report)
                print(
                    f"{fixture['id']} repeat{repeat}: {record['audit_status']} trace={record['complete_process_network_admission']}",
                    flush=True,
                )
            # Only two valid fact sets can establish repeat equality.
            equal = normalized[0] == normalized[1] if len(normalized) == 2 else None
            for record in records[-2:]:
                record["paired_raw_facts_equal"] = equal
            checkpoint(output, report)
        if (
            identity(binary) != initial
            or digest(manifest_path) != report["preparation_sha256"]
            or digest(tracer) != report["tracer_sha256"]
        ):
            raise ValueError("provider-final-identity-mismatch")
        report["status"] = "completed-diagnostic-only"
        report["full_contract_qualified"] = False
        checkpoint(output, report)
    except BaseException as error:
        report["status"] = "aborted"
        report["abort_error"] = f"{type(error).__name__}: {error}"[:4096]
        for record in records:
            record["comparative_acceptance"] = False
        checkpoint(output, report)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--strace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.binary.resolve(), args.manifest.resolve(), args.strace.resolve(), args.output.resolve())


if __name__ == "__main__":
    main()
