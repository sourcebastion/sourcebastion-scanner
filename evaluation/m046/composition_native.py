"""One finite multi-root composition fixture, twice; not engine qualification."""

import argparse
import json
from pathlib import Path
import platform
import resource
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from evaluation.m046.composition_spike import compose
from evaluation.m046.provider_native import audit_child
from evaluation.m046.run import MAX_OUTPUT, digest, execute, snapshot
from evaluation.m046.static_cli import encode
from evaluation.m046.static_inputs import Source
from evaluation.m046.syft_control_audit import decode
from evaluation.m046.syft_control_benchmark import checkpoint
from evaluation.m046.syft_native import candidate_source_identity, identity, native_elf, trace_admission

FILES = {
    "a/requirements.txt": "pip==26.0.1\n",
    "b/requirements.txt": "pip==26.0.1\n",
    "site-packages/pip-26.0.1.dist-info/METADATA": "Metadata-Version: 2.1\nName: pip\nVersion: 26.0.1\nRequires-Dist: packaging>=24\n",
    "site-packages/pip-26.0.1.dist-info/RECORD": "",
    "web/package.json": json.dumps({"name": "fixture", "version": "1.0.0", "dependencies": {"debug": "^4.3.7"}}),
    "web/package-lock.json": json.dumps(
        {
            "name": "fixture",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "fixture", "version": "1.0.0", "dependencies": {"debug": "^4.3.7"}},
                "node_modules/debug": {
                    "version": "4.3.7",
                    "resolved": "https://packages.invalid/debug.tgz",
                    "dependencies": {"ms": "^2.1.3"},
                },
                "node_modules/ms": {"version": "2.1.3", "resolved": "https://packages.invalid/ms.tgz"},
            },
        }
    ),
    "go/go.mod": "module example.test/fixture\n\ngo 1.22\nrequire example.test/dependency v1.0.0\nreplace example.test/dependency => ../dependency\n",
    "go-min/go.mod": "module example.test/minimum\n\ngo 1.22\nrequire example.test/declared v1.0.0\n",
}


def code_identity():
    return {path.name: digest(path) for path in sorted(Path(__file__).parent.glob("*.py"))}


def audit(root, raw, destination):
    resource.setrlimit(resource.RLIMIT_AS, (1024**3,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT,) * 2)
    if raw.stat().st_size > MAX_OUTPUT:
        raise ValueError("composition-raw-limit")
    with Source(root) as source:
        result = compose(source, decode(raw.read_bytes()))
    content = encode(result)
    with destination.open("xb") as stream:
        stream.write(content)
    # Independent post-extraction synthetic assertions; never extraction inputs.
    occurrences = result["source_occurrences"]
    if sorted((r["occurrence"]["root"], r["occurrence"]["package"]) for r in occurrences) != [
        ("a", "pypi:pip@26.0.1"),
        ("b", "pypi:pip@26.0.1"),
    ]:
        raise ValueError("composition-root-occurrence-proof-failed")
    rows = result["provider_evidence"]
    roles = {r["role"] for r in rows}
    if (
        not {
            "installed-version-evidence",
            "application-metadata",
            "unselected-versionless-metadata",
            "declaration-candidate",
            "lock-evidence-unadapted",
        }
        <= roles
    ):
        raise ValueError("composition-role-proof-failed")
    eligible = [r for r in rows if r["match_eligible_identity_evidence"]]
    if len(eligible) != 1 or eligible[0]["record"]["identity"] != "pypi:pip@26.0.1":
        raise ValueError("composition-installed-separation-proof-failed")
    if len({r["id"] for r in occurrences + rows}) != len(occurrences) + len(rows):
        raise ValueError("composition-identity-collision")
    edges = result["provider_relations"]
    if not any(
        r["parent"] == "npm:debug@4.3.7"
        and r["child"] == "npm:ms@2.1.3"
        and r["shared_evidence_paths"] == ["web/package-lock.json"]
        and r["analysis_scopes"] == ["web"]
        and r["matching_edge"] is False
        for r in edges
    ):
        raise ValueError("composition-edge-context-proof-failed")
    sys.stdout.buffer.write(
        encode(
            {
                "composition_sha256": digest(destination),
                "source_occurrences": len(occurrences),
                "provider_records": len(rows),
                "provider_edges": len(edges),
                "roles": sorted(roles),
                "full_contract_qualified": False,
            }
        )
    )


def run(binary, manifest, tracer, output):
    native_elf(binary)
    initial, code, tracer_hash, manifest_hash = identity(binary), code_identity(), digest(tracer), digest(manifest)
    preparation = decode(manifest.read_bytes())
    if (
        preparation["binary_sha256"] != initial["binary_sha256"]
        or preparation["candidate_sources"] != candidate_source_identity()
    ):
        raise ValueError("composition-preparation-mismatch")
    output.mkdir(parents=True, exist_ok=False)
    root = output / "source"
    for path, content in FILES.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content)
    before = snapshot(root)
    (output / "source-snapshot.json").write_bytes(encode(before))
    report = {
        "status": "running",
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "binary": initial,
        "code_sha256": code,
        "tracer_sha256": tracer_hash,
        "preparation_sha256": manifest_hash,
        "records": [],
        "plan": [{"repeat": repeat} for repeat in range(2)],
        "full_contract_qualified": False,
        "scope": "two small synthetic composition attempts; no aggregate resource, Alpine, standard export or production acceptance",
    }
    checkpoint(output, report)
    try:
        for repeat in range(2):
            directory = output / str(repeat)
            directory.mkdir()
            record = {"repeat": repeat, "attempt_status": "started"}
            report["records"].append(record)
            checkpoint(output, report)
            record["result"] = execute(
                root,
                directory,
                tracer,
                [str(binary), "--root", str(root), "--mode", "provider", "--generate-cpes=false", "--timeout=40s"],
                45,
            )
            if record["result"]["exit_code"] != 0 or record["result"]["timed_out"]:
                raise ValueError("composition-provider-execution-invalid")
            raw, trace = directory / "stdout.log", directory / "trace.log"
            if raw.stat().st_size > MAX_OUTPUT or trace.stat().st_size > MAX_OUTPUT:
                raise ValueError("composition-evidence-limit")
            record.update(raw_sha256=digest(raw), trace_sha256=digest(trace))
            try:
                record["trace"] = trace_admission(trace.read_text(), binary, require_complete=True)
                record["strict_trace_admitted"] = True
            except ValueError as error:
                record.update(strict_trace_admitted=False, trace_refusal=str(error))
            with (directory / "audit.stdout").open("wb") as stdout, (directory / "audit.stderr").open("wb") as stderr:
                status = audit_child(
                    [
                        sys.executable,
                        "-I",
                        "-B",
                        str(Path(__file__).resolve()),
                        "--audit",
                        "--root",
                        str(root),
                        "--raw",
                        str(raw),
                        "--output",
                        str(directory / "composition.json"),
                    ],
                    stdout,
                    stderr,
                )
            if status != 0 or (directory / "audit.stdout").stat().st_size > 1024 * 1024:
                raise ValueError("composition-audit-refused")
            record["audit"] = decode((directory / "audit.stdout").read_bytes())
            if digest(directory / "composition.json") != record["audit"]["composition_sha256"]:
                raise ValueError("composition-output-identity-mismatch")
            if (
                snapshot(root) != before
                or identity(binary) != initial
                or code_identity() != code
                or digest(tracer) != tracer_hash
                or digest(manifest) != manifest_hash
            ):
                raise ValueError("composition-source-or-code-changed")
            record["attempt_status"] = "completed"
            checkpoint(output, report)
        report["repeat_composition_equal"] = report["records"][0]["audit"] == report["records"][1]["audit"]
        if not report["repeat_composition_equal"]:
            raise ValueError("composition-repeat-disagreement")
        report["status"] = "completed-diagnostic-only"
        checkpoint(output, report)
    except BaseException as error:
        report.update(
            status="aborted", abort_error=f"{type(error).__name__}: {error}"[:4096], comparative_acceptance=False
        )
        checkpoint(output, report)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", action="store_true")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--strace", type=Path)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--raw", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.audit:
        audit(args.root.resolve(strict=True), args.raw.resolve(strict=True), args.output.resolve())
    else:
        run(
            args.binary.resolve(strict=True),
            args.manifest.resolve(strict=True),
            args.strace.resolve(strict=True),
            args.output.resolve(),
        )


if __name__ == "__main__":
    main()
