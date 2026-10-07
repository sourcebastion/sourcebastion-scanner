"""Controlled native extended-Syft correctness and CPE diagnostics, not resources."""

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import quote

from .benchmark import native_elf
from .corpus import CORPUS
from .run import MAX_OUTPUT, compare, digest, execute, materialize, snapshot
from .static_native import NETWORK_SYSCALLS, SUPPORTED_MANIFESTS, runtime_identity, source_identity, supported

CONTROLS = {"python-requirements", "node-npm-complete", "go-module", "java-gradle-lock"}


def trace_calls(trace):
    calls, pending = [], {}
    for line in trace.splitlines():
        prefix = re.match(r"^\s*(?:(\d+)\s+|\[pid\s+(\d+)\]\s+)?(.*)$", line)
        pid, body = prefix[1] or prefix[2], prefix[3]
        resumed = re.match(r"<\.\.\. ([a-z][a-z0-9_]*) resumed>(.*)$", body)
        if resumed:
            start = pending.pop(pid, None)
            if start is None or start[0] != resumed[1]:
                raise ValueError("syft-incomplete-process-trace")
            name, arguments = start[0], start[1] + resumed[2]
        else:
            start = re.match(r"([a-z][a-z0-9_]*)\((.*)$", body)
            if start is None:
                continue
            name, arguments = start[1], start[2]
            if arguments.endswith("<unfinished ...>"):
                if pid in pending:
                    raise ValueError("syft-incomplete-process-trace")
                pending[pid] = (name, arguments.removesuffix("<unfinished ...>").rstrip())
                continue
        calls.append((pid, name, arguments))
    if pending:
        raise ValueError("syft-incomplete-process-trace")
    return calls


def trace_admission(trace, binary, python=None):
    invocations = trace_calls(trace)
    executions, process_calls, probes, go_threads = [], [], [], set()
    for position, (pid, name, arguments) in enumerate(invocations):
        if name in NETWORK_SYSCALLS or name == "execveat":
            raise ValueError("syft-network-or-untrusted-process-attempt")
        if name == "execve":
            filename, _end = json.JSONDecoder().raw_decode(arguments)
            executions.append(filename)
            if filename == str(binary) and len(executions) == 1:
                go_threads.add(pid)
        if name in {"clone", "clone3"} and "CLONE_THREAD" in arguments and pid in go_threads:
            child = re.search(r"\)\s*= (\d+)$", arguments)
            if child:
                go_threads.add(child[1])
        if name in {"fork", "vfork", "clone", "clone3"} and "CLONE_THREAD" not in arguments:
            # Go1.27.1 syscall.doCheckClonePidfd uses an exit-only child with
            # these exact flags and reaps it with __WCLONE. Admit that one
            # runtime capability probe, never arbitrary additional children.
            probe = (
                re.fullmatch(
                    r"child_stack=NULL, flags=CLONE_VM\|CLONE_PIDFD\|CLONE_VFORK, parent_tid=\[(\d+)\]\)\s*= ([1-9]\d*)",
                    arguments,
                )
                if name == "clone" and python and pid in go_threads and len(executions) == 1
                else None
            )
            if probe:
                descriptor, child = probe[1], probe[2]
                child_calls = [(call, args) for who, call, args in invocations if who == child]
                python_position = next(
                    (
                        index
                        for index, (_who, call, args) in enumerate(invocations)
                        if call == "execve" and json.JSONDecoder().raw_decode(args)[0] == str(python)
                    ),
                    -1,
                )
                reaped = any(
                    who == pid
                    and call == "waitid"
                    and position < index < python_position
                    and args.startswith(f"P_PIDFD, {descriptor}, {{")
                    and re.search(rf"\bsi_pid={child},", args)
                    and "si_status=0," in args
                    and "si_code=CLD_EXITED," in args
                    and "si_signo=SIGCHLD," in args
                    and re.search(r"\}, WEXITED\|__WCLONE, NULL\)\s*= 0$", args)
                    for index, (who, call, args) in enumerate(invocations)
                )
                if (
                    len(child_calls) != 1
                    or child_calls[0][0] != "exit_group"
                    or not re.fullmatch(r"0\)\s*= \?", child_calls[0][1])
                    or not reaped
                ):
                    raise ValueError("syft-untrusted-pidfd-probe")
                probes.append(child)
                continue
            process_calls.append(name)
    expected = [str(binary)] + ([str(python)] if python else [])
    if executions != expected or len(process_calls) != (1 if python else 0) or len(probes) > 1:
        raise ValueError("syft-untrusted-process-attempt")
    return {
        "executions": executions,
        "nonthread_process_calls": process_calls,
        "pidfd_probe_children": probes,
        "network_attempts": 0,
    }


def non_cpe(document):
    copy = deepcopy(document)
    copy.pop("descriptor", None)  # Tool config records the experimental toggle.
    for artifact in copy["artifacts"]:
        artifact.pop("cpes", None)
    # Concurrent cataloger result ordering is not semantic.
    for key in ("artifacts", "artifactRelationships", "files"):
        if isinstance(copy.get(key), list):
            copy[key].sort(key=lambda value: json.dumps(value, sort_keys=True))
    return copy


def verify_projection(bundle):
    sidecar = bundle["sidecar"]
    occurrences = sidecar["inventory"]["semantic_dimensions"]["occurrences"]
    artifacts = bundle["syft"]["artifacts"]
    custom_records = [record for record in artifacts if record["foundBy"] == "m046-static-python-cataloger"]
    custom = {record["id"]: record for record in custom_records}
    if len(custom) != len(custom_records):
        raise ValueError("syft-duplicate-occurrence-id")
    bindings = sidecar["projection"]["occurrences"]
    if len(custom) != len(occurrences) or len(bindings) != len(occurrences):
        raise ValueError("syft-occurrence-count-mismatch")
    if {binding["index"] for binding in bindings} != set(range(len(occurrences))):
        raise ValueError("syft-occurrence-index-mismatch")
    if {binding["syft_id"] for binding in bindings} != set(custom):
        raise ValueError("syft-occurrence-id-mismatch")
    for binding in bindings:
        occurrence = occurrences[binding["index"]]
        artifact = custom[binding["syft_id"]]
        name, version = occurrence["package"][5:].split("@", 1)
        canonical_occurrence = json.dumps(occurrence, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        for character, escape in [
            ("<", r"\u003c"),
            (">", r"\u003e"),
            ("&", r"\u0026"),
            ("\u2028", r"\u2028"),
            ("\u2029", r"\u2029"),
        ]:
            canonical_occurrence = canonical_occurrence.replace(character, escape)
        expected_id = (
            "m046-"
            + hashlib.sha256(
                b"m046-syft-occurrence-v1\0m046-static-inventory-prototype-v5\0" + canonical_occurrence.encode("utf-8")
            ).hexdigest()
        )
        if (
            artifact["id"] != expected_id
            or artifact.get("purl") != f"pkg:pypi/{quote(name, safe='-._~')}@{quote(version, safe='-._~')}"
        ):
            raise ValueError("syft-occurrence-id-or-purl-mismatch")
        if (artifact["name"], artifact["version"], artifact["type"]) != (name, version, "python"):
            raise ValueError("syft-occurrence-selection-mismatch")
        locations = artifact["locations"]
        if not any(
            location["path"] == occurrence["path"]
            and location.get("annotations", {}).get("m046:locator") == occurrence["locator"]
            and location.get("annotations", {}).get("m046:occurrence") == artifact["id"]
            for location in locations
        ):
            raise ValueError("syft-occurrence-location-mismatch")
    projected = sidecar["projection"]["relationships"]
    unmapped = sidecar["projection"]["unmapped_relationships"]
    rich_edges = sidecar["inventory"]["semantic_dimensions"]["relationships"]
    indices = [edge["index"] for edge in projected] + unmapped
    if sorted(indices) != list(range(len(rich_edges))):
        raise ValueError("syft-relationship-accounting-mismatch")
    # Recompute endpoints from verified occurrences, independently of the
    # adapter's claimed projection. Equal artifact/sidecar claims alone do not
    # establish that the projected graph has the rich edge's provenance.
    occurrence_ids = {binding["index"]: binding["syft_id"] for binding in bindings}
    occurrence_index = {}
    for index, occurrence in enumerate(occurrences):
        key = (occurrence["root"], occurrence["path"], occurrence["package"])
        occurrence_index.setdefault(key, []).append(index)
    expected_projected, expected_unmapped, expected_reasons = [], [], {}
    steps = 0
    for index, edge in enumerate(rich_edges):
        candidates = []
        for endpoint in ("parent", "child"):
            matches = []
            locator = edge.get(f"{endpoint}_locator")
            for number in occurrence_index.get((edge["root"], edge["path"], edge[endpoint]), []):
                steps += 1
                if steps > 5_000_000:
                    raise ValueError("syft-verification-step-budget-exceeded")
                actual_locator = occurrences[number]["locator"]
                if (
                    locator is None
                    or actual_locator == locator
                    or (endpoint == "child" and actual_locator.startswith(locator + ".groups["))
                ):
                    matches.append(number)
            candidates.append(matches)
        parents, children = candidates
        if len(parents) == len(children) == 1:
            expected_projected.append(
                {
                    "index": index,
                    "parent_syft_id": occurrence_ids[parents[0]],
                    "child_syft_id": occurrence_ids[children[0]],
                }
            )
        else:
            expected_unmapped.append(index)
            expected_reasons[str(index)] = (
                "missing-parent-occurrence"
                if not parents
                else (
                    "ambiguous-parent-occurrence"
                    if len(parents) > 1
                    else "missing-child-occurrence" if not children else "ambiguous-child-occurrence"
                )
            )
    if (
        projected != expected_projected
        or unmapped != expected_unmapped
        or sidecar["projection"].get("unmapped_reasons", {}) != expected_reasons
    ):
        raise ValueError("syft-relationship-provenance-mismatch")
    actual = [
        edge for edge in bundle["syft"]["artifactRelationships"] if edge["type"] == "m046-informational-dependency"
    ]
    wanted = [(edge["child_syft_id"], edge["parent_syft_id"], rich_edges[edge["index"]]) for edge in projected]
    canonical = lambda rows: sorted(json.dumps(row, sort_keys=True) for row in rows)
    if canonical(wanted) != canonical([(edge["parent"], edge["child"], edge.get("metadata")) for edge in actual]):
        raise ValueError("syft-informational-edge-mismatch")
    return {"occurrences": len(bindings), "relationships": len(projected), "unmapped_relationships": len(unmapped)}


def candidate_source_identity():
    root = Path(__file__).with_name("syft_extension")
    files = {str(path.relative_to(root)): digest(path) for path in sorted(root.rglob("*")) if path.is_file()}
    return {
        "frontend": source_identity(),
        "go_sources": files,
        "tools_pin_sha256": digest(Path(__file__).with_name("tools.json")),
    }


def identity(binary):
    return {**candidate_source_identity(), "binary_sha256": digest(binary)}


def run(output, tracer, binary, preparation_manifest):
    runtime = runtime_identity()
    native_elf(binary)
    before_identity = identity(binary)
    preparation = json.loads(preparation_manifest.read_text())
    if (
        preparation["binary_sha256"] != before_identity["binary_sha256"]
        or preparation["candidate_sources"] != candidate_source_identity()
    ):
        raise ValueError("syft-preparation-source-or-binary-mismatch")
    output.mkdir(parents=True, exist_ok=False)
    records, controls = [], []
    for fixture in CORPUS:
        directory = output / fixture["id"]
        directory.mkdir()
        source = directory / "source"
        materialize(fixture, source)
        before = snapshot(source)
        modes = [("extended", False)]
        if fixture["id"] in CONTROLS:
            modes.extend([("control", False), ("control", True)])
        control_documents = []
        for mode, cpes in modes:
            scratch = directory / f"{mode}-{cpes}"
            scratch.mkdir()
            command = [
                str(binary),
                "--root",
                str(source),
                f"--generate-cpes={str(cpes).lower()}",
                "--timeout=40s",
                "--mode",
                mode,
            ]
            if mode == "extended":
                command.extend(
                    ["--python", sys.executable, "--frontend", str(Path(__file__).with_name("static_cli.py"))]
                )
            result = execute(source, scratch, tracer, command, 45)
            if result["timed_out"] or result["exit_code"] != 0 or snapshot(source) != before:
                raise ValueError("syft-native-invocation-invalid")
            if (scratch / "stdout.log").stat().st_size > MAX_OUTPUT:
                raise ValueError("syft-native-output-budget-exceeded")
            content = (scratch / "stdout.log").read_bytes()
            document = json.loads(content)
            admission = trace_admission(
                (scratch / "trace.log").read_text(), binary, sys.executable if mode == "extended" else None
            )
            record = {
                "fixture": fixture["id"],
                "mode": mode,
                "generate_cpes": cpes,
                "result": result,
                "trace": admission,
                "raw_sha256": hashlib.sha256(content).hexdigest(),
                "trace_sha256": digest(scratch / "trace.log"),
            }
            if mode == "extended":
                record["projection"] = verify_projection(document)
                record["comparison"] = compare(fixture["expected"], document["sidecar"]["inventory"])
                admitted = supported(fixture) or fixture["id"] in SUPPORTED_MANIFESTS
                record["required_rich_contract"] = admitted
                if admitted and not record["comparison"]["full_contract_agreement"]:
                    raise ValueError("syft-native-rich-oracle-mismatch")
            else:
                control_documents.append(document)
                record["cpe_count"] = sum(len(artifact["cpes"]) for artifact in document["artifacts"])
            (scratch / "record.json").write_text(json.dumps(record, indent=2) + "\n")
            records.append(record)
        if control_documents:
            equal = non_cpe(control_documents[0]) == non_cpe(control_documents[1])
            if not equal:
                raise ValueError("syft-cpe-control-changed-other-inventory")
            controls.append({"fixture": fixture["id"], "non_cpe_inventory_equal": equal})
        if identity(binary) != before_identity:
            raise ValueError("syft-controller-source-changed")
    summary = {
        "status": "controlled-correctness-only",
        "runtime": runtime,
        "source_before": before_identity,
        "source_after": identity(binary),
        "preparation_manifest_sha256": digest(preparation_manifest),
        "tracer_sha256": digest(tracer),
        "records": records,
        "controls": controls,
        "resource_engine_production_S01_acceptance": "not-assessed",
        "file_mutation_admission": "manual raw file-trace audit required; snapshots prove retained changes only",
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--strace", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--preparation-manifest", required=True, type=Path)
    args = parser.parse_args()
    run(args.output.resolve(), args.strace.resolve(), args.binary.resolve(), args.preparation_manifest.resolve())


if __name__ == "__main__":
    main()
