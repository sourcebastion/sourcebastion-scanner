"""Native fixed Go parser proof; private synthetic source observations only."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

from sourcebastion.inventory import go_sources, compose_go, compose_source, compose_requirements, provider
from sourcebastion.inventory.contract import Producer, canonical_bytes
from sourcebastion.inventory.inputs import Source, InputRefusal
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256
import time


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require_unoptimized():
    if sys.flags.optimize:
        raise RuntimeError("optimized-probe-runtime-refused")


def verify(binary, preparation):
    require_unoptimized()
    manifest = json.loads(preparation.read_bytes())
    assert digest(binary.read_bytes()) == manifest["go_source_binary_sha256"]
    assert binary.stat().st_size == manifest["go_source_binary_bytes"]
    expected_arch = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    assert manifest["architecture"] == expected_arch and manifest["cgo_enabled"] == "0"
    source = Path("cmd/inventory-provider")
    for name, sha in manifest["source_files"].items():
        assert digest((source / name).read_bytes()) == sha
    records = []
    deadline = time.monotonic() + 150

    def run(label, content, *, success=True, output_limit=64 * 1024 * 1024):
        remaining = deadline - time.monotonic()
        assert remaining > 0
        process = subprocess.run(
            [str(binary), "--remaining", f"{remaining}s", "--output-bytes", str(output_limit)],
            input=content,
            capture_output=True,
            timeout=remaining,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
        assert len(process.stdout) <= output_limit and len(process.stderr) <= 128
        if success:
            assert process.returncode == 0 and not process.stderr
            result = json.loads(process.stdout)
            assert result["source_sha256"] == digest(content)
            assert result["parser"] == "golang.org/x/mod/modfile@v0.41.0"
            assert result["selected_versions"] == "unreported" and result["graph"] == "unreported"
        else:
            assert process.returncode != 0 and not process.stdout
            assert process.stderr.decode().strip() in {
                "invalid-go-source-syntax",
                "unsupported-go-requirement-identity",
                "unsupported-go-module-identity",
                "go-source-input-refused",
                "go-source-output-budget-exceeded",
            }
            result = {"reason": process.stderr.decode().strip()}
        records.append({"case": label, "source_sha256": digest(content), "result": result})
        return result

    basic = b'module "example.invalid/root"\ngo 1.24\nrequire (\n "example.invalid/alpha" "v1.2.3" // indirect\n example.invalid/beta/v2 v2.0.0\n)\n'
    result = run("quoted-minimums", basic)
    assert len(result["requirements"]) == 2
    first = result["requirements"][0]
    assert first["minimum_version"] == "v1.2.3" and first["indirect"] and first["line"] == 4
    assert b"alpha" in basic[first["start_byte"] : first["end_byte"]]
    assert not result["unassessed_directives"]
    assert run("repeat-canonical", basic) == result
    controlled = b"module example.invalid/root\nrequire example.invalid/alpha v1.2.3\nrequire example.invalid/alpha v1.2.4\nreplace example.invalid/alpha => ../private-secret\nexclude example.invalid/beta v1.0.0\ntoolchain go1.27.1\n"
    result = run("controls-and-duplicates", controlled)
    assert len(result["requirements"]) == 2 and len(result["unassessed_directives"]) == 4
    assert "private-secret" not in json.dumps(result)
    for label, content in [
        ("unknown-directive", b"module example.invalid/root\nfuture private-secret\n"),
        ("private-identity", b"module example.invalid/root\nrequire https://user:secret@example.invalid/pkg v1.2.3\n"),
        ("major-mismatch", b"module example.invalid/root\nrequire example.invalid/pkg/v2 v1.2.3\n"),
        ("missing-module", b"require example.invalid/pkg v1.2.3\n"),
        ("input-budget", b"a" * (2 * 1024 * 1024 + 1)),
    ]:
        run(label, content, success=False)
    run("output-budget", basic, success=False, output_limit=1)
    # Force output backpressure without consuming stdout. Both native
    # architectures must exit on their own deadline, rather than rely on
    # this proof's outer timeout killing a hung executable.
    blocked_input = b"module example.invalid/root\n" + b"".join(
        f"require example.invalid/package{number} v1.2.3\n".encode() for number in range(2000)
    )
    process = subprocess.Popen(
        [str(binary), "--remaining", "300ms"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pipesize=4096,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
    )
    try:
        process.stdin.write(blocked_input)
        process.stdin.close()
        process.wait(timeout=3)
        partial = process.stdout.read()
        diagnostic = process.stderr.read()
        assert process.returncode != 0 and diagnostic == b"go-source-deadline-exceeded\n"
        assert 0 < len(partial) <= 4096
        records.append(
            {
                "case": "blocked-output-deadline",
                "source_sha256": digest(blocked_input),
                "result": {"reason": "go-source-deadline-exceeded", "partial_bytes": len(partial)},
            }
        )
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()
        if not process.stdin.closed:
            process.stdin.close()
    # Exercise the installed Python bridge with the source-bound executable.
    modules = (go_sources, compose_go, compose_source, compose_requirements, provider)
    module_hashes = {}
    for module in modules:
        loaded = Path(module.__file__).resolve()
        expected = Path(*module.__name__.split(".")).with_suffix(".py")
        assert loaded != expected.resolve()
        assert digest(loaded.read_bytes()) == digest(expected.read_bytes())
        module_hashes[module.__name__] = digest(loaded.read_bytes())
    runtime = go_sources.Runtime(binary, manifest["go_source_binary_sha256"])
    config = DiscoveryConfig()
    producer = Producer(
        name="native-go-source",
        version="1",
        code_sha256=digest(Path(__file__).read_bytes()),
        registry_sha256=REGISTRY_SHA256,
        config_sha256=config.sha256,
    )

    def composed(files, *, config=config):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            with Source(root) as source:
                return compose_source.compose_source(
                    source,
                    source_sha256=digest(basic),
                    producer=producer.model_copy(update={"config_sha256": config.sha256}),
                    config=config,
                    go_runtime=runtime,
                )

    canonical_records = []
    for label, files in [
        ("minimum-not-selected", {"go.mod": basic}),
        (
            "checksum-history-not-selection",
            {"go.mod": basic, "go.sum": b"example.invalid/alpha v9.9.9 h1:" + b"a" * 43 + b"=\n"},
        ),
        ("multiple-explicit-projects", {"one/go.mod": basic, "two/go.mod": basic.replace(b"root", b"next")}),
        ("controls-partial", {"go.mod": controlled}),
        ("malformed-file-local", {"go.mod": b"future private-secret\n", "requirements.txt": b"pip==26.0.1\n"}),
    ]:
        result = composed(files)
        encoded = canonical_bytes(result)
        assert result.stages.inventory == "partial" and not result.relationships
        if label == "malformed-file-local":
            assert [(r.name, r.selected_version) for r in result.occurrences] == [("pip", "26.0.1")]
        else:
            assert result.occurrences and all(
                r.selected_version is None and r.activation == "unknown" for r in result.occurrences
            )
            assert all(r.exact_version is None for r in result.declarations)
            assert all(app.version is None for app in result.applications)
        if label == "multiple-explicit-projects":
            assert len(result.roots) == 2 and len({r.root_id for r in result.occurrences}) == 2
        if label == "checksum-history-not-selection":
            assert len(result.occurrences) == 2 and any(
                r.reason == "unassessed-go-checksum-history" for r in result.coverage.inputs
            )
        assert b"private-secret" not in encoded
        assert encoded == canonical_bytes(composed(files))
        canonical_records.append({"case": label, "canonical_sha256": digest(encoded)})
    result = composed(
        {"go.mod": basic, "requirements.txt": b"pip==26.0.1\n"}, config=DiscoveryConfig(semantic_checks=80)
    )
    assert result.stages.inventory == "failed" and not result.occurrences and not result.declarations
    canonical_records.append({"case": "shared-budget-global", "canonical_sha256": digest(canonical_bytes(result))})
    original_parse = go_sources.parse
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "go.mod").write_bytes(basic)
        (root / "requirements.txt").write_bytes(b"pip==26.0.1\n")

        def changed_source(content, **kwargs):
            observed = original_parse(content, **kwargs)
            (root / "go.mod").write_bytes(content.replace(b"v1.2.3", b"v1.2.4"))
            return observed

        go_sources.parse = changed_source
        try:
            with Source(root) as source:
                result = compose_source.compose_source(
                    source, source_sha256=digest(basic), producer=producer, config=config, go_runtime=runtime
                )
        finally:
            go_sources.parse = original_parse
        assert result.stages.inventory == "failed" and not result.occurrences and not result.declarations
        canonical_records.append(
            {"case": "source-mutation-global", "canonical_sha256": digest(canonical_bytes(result))}
        )
    original_run = go_sources.subprocess.run
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        copied = root / "trusted-helper"
        copied.write_bytes(binary.read_bytes())
        copied.chmod(0o700)
        local_runtime = go_sources.Runtime(copied, runtime.sha256)
        checkout = root / "checkout"
        checkout.mkdir()
        (checkout / "go.mod").write_bytes(basic)
        (checkout / "requirements.txt").write_bytes(b"pip==26.0.1\n")

        def changed_runtime(*args, **kwargs):
            process = original_run(*args, **kwargs)
            copied.unlink()
            return process

        go_sources.subprocess.run = changed_runtime
        try:
            with Source(checkout) as source:
                result = compose_source.compose_source(
                    source, source_sha256=digest(basic), producer=producer, config=config, go_runtime=local_runtime
                )
        finally:
            go_sources.subprocess.run = original_run
        assert result.stages.inventory == "failed" and not result.occurrences and not result.declarations
        assert "changed-go-parser-runtime" in result.coverage.refusal_codes
        canonical_records.append(
            {"case": "helper-mutation-global", "canonical_sha256": digest(canonical_bytes(result))}
        )
    print(
        json.dumps(
            {
                "schema_version": "sourcebastion.go-source-native-proof/1",
                "status": "native-go-source-passed",
                "architecture": expected_arch,
                "python": platform.python_version(),
                "binary_sha256": manifest["go_source_binary_sha256"],
                "source_files": manifest["source_files"],
                "cases": records,
                "canonical_cases": canonical_records,
                "source_modules": module_hashes,
                "scope": "finite maintained Go source parser observations; no selected versions, canonical graph, production route, rich corpus or whole-pipeline resource acceptance",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    try:
        require_unoptimized()
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--binary", required=True, type=Path)
        parser.add_argument("--preparation", required=True, type=Path)
        args = parser.parse_args()
        verify(args.binary, args.preparation)
    except Exception as error:
        print(json.dumps({"status": "native-go-source-failed", "reason": type(error).__name__}))
        raise
