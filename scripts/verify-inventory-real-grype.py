"""Finite native Grype integration evidence; no production controller or release."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

FIXTURE = Path("evaluation/m046/real-grype-native-fixture-v2.json")
PINS = Path("evaluation/m046/real-grype-native-binaries-v1.json")
BINARY = Path("/usr/local/bin/grype")
ADVISORIES = Path("/advisories")
OUTPUT = Path("/out")
STDOUT_BYTES = 2 * 1024 * 1024
STDERR_BYTES = 256 * 1024
ADVISORY_BYTES = 4 * 1024**3


def render(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_nlink,
    )


def guard(deadline):
    if time.monotonic() >= deadline:
        raise RuntimeError("real-grype-proof-deadline-exceeded")


def file_binding(path, *, maximum, deadline):
    """Stream one regular, single-link file; retain visible/held identities."""
    guard(deadline)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
        raise ValueError("real-grype-proof-unsafe-file")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as handle:
        if identity(os.fstat(handle.fileno())) != identity(before):
            raise ValueError("real-grype-proof-changed-file")
        digest, total = hashlib.sha256(), 0
        while True:
            guard(deadline)
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ValueError("real-grype-proof-file-budget-exceeded")
            digest.update(chunk)
        if total != before.st_size or identity(os.fstat(handle.fileno())) != identity(before):
            raise ValueError("real-grype-proof-changed-file")
    if identity(path.lstat()) != identity(before):
        raise ValueError("real-grype-proof-changed-file")
    return {"sha256": digest.hexdigest(), "bytes": total, "metadata": identity(before)}


def advisory_binding(root, deadline):
    """Finite readonly-mount diagnostic, not same-UID administrator fencing."""
    pending, directories, files, total = [(root, 0)], {}, {}, 0
    while pending:
        guard(deadline)
        path, depth = pending.pop()
        info = path.lstat()
        if depth > 8 or not stat.S_ISDIR(info.st_mode):
            raise ValueError("real-grype-proof-unsafe-advisory-directory")
        directories[str(path.relative_to(root))] = identity(info)
        if len(directories) > 32:
            raise ValueError("real-grype-proof-advisory-entry-budget-exceeded")
        with os.scandir(path) as entries:
            for entry in entries:
                guard(deadline)
                child = Path(entry.path)
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    pending.append((child, depth + 1))
                    if len(pending) + len(directories) > 32:
                        raise ValueError("real-grype-proof-advisory-entry-budget-exceeded")
                else:
                    if len(files) >= 32:
                        raise ValueError("real-grype-proof-advisory-entry-budget-exceeded")
                    binding = file_binding(child, maximum=ADVISORY_BYTES - total, deadline=deadline)
                    total += binding["bytes"]
                    files[child.relative_to(root).as_posix()] = binding
    if not {"snapshot.json", "6/vulnerability.db"} <= files.keys():
        raise ValueError("real-grype-proof-missing-advisory-files")
    for relative, expected in directories.items():
        if identity((root / relative).lstat()) != expected:
            raise ValueError("real-grype-proof-changed-advisory-directory")
    return {"directories": directories, "files": files}


def capture(command, *, environment, cwd, stdout, stderr, deadline, check):
    """Bound both pipes while running; kill/reap the process group on failure."""
    check()
    guard(deadline)
    sizes = {"stdout": 0, "stderr": 0}
    ceilings = {"stdout": STDOUT_BYTES, "stderr": STDERR_BYTES}
    with stdout.open("xb") as out, stderr.open("xb") as err, selectors.DefaultSelector() as selector:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=environment,
            start_new_session=True,
            close_fds=True,
        )
        try:
            for label, pipe, target in (("stdout", process.stdout, out), ("stderr", process.stderr, err)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, (label, target))
            while selector.get_map():
                check()
                guard(deadline)
                for key, _ in selector.select(min(0.25, max(0, deadline - time.monotonic()))):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    label, target = key.data
                    remaining = ceilings[label] - sizes[label]
                    target.write(chunk[:remaining])
                    sizes[label] += len(chunk)
                    if sizes[label] > ceilings[label]:
                        raise RuntimeError("real-grype-proof-" + label + "-budget-exceeded")
            check()
            guard(deadline)
            if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
                raise RuntimeError("real-grype-proof-consumer-nonzero-exit")
            check()
            guard(deadline)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            raise
        finally:
            for pipe in (process.stdout, process.stderr):
                pipe.close()
    return {"argv": command, "exit_code": process.returncode, "captured_bytes": sizes}


def modules(root, deadline):
    result = {}
    for path in sorted(root.rglob("*")):
        guard(deadline)
        if path.is_file() and path.suffix in {".py", ".cjs", ".js", ".json", ".mjs"}:
            if len(result) >= 256:
                raise ValueError("real-grype-proof-module-count-exceeded")
            result[path.relative_to(root).as_posix()] = file_binding(
                path,
                maximum=2 * 1024 * 1024,
                deadline=deadline,
            )["sha256"]
    return result


def known_advisory(match, aliases):
    rows = [match["vulnerability"], *match.get("relatedVulnerabilities", [])]
    return any((row.get("id"), row.get("namespace")) in aliases for row in rows if type(row) is dict)


def verify():
    if sys.flags.optimize:
        raise RuntimeError("optimized-probe-runtime-refused")
    if os.getuid() == 0:
        raise RuntimeError("real-grype-proof-root-refused")
    from sourcebastion.inventory import contract
    from sourcebastion.inventory.compose_source import compose_source
    from sourcebastion.inventory.contract import Producer, canonical_bytes
    from sourcebastion.inventory.cyclonedx import export
    from sourcebastion.inventory.inputs import Source
    from sourcebastion.inventory.matching import Consumer, recover
    from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256

    admission_start = time.monotonic()
    admission_deadline = admission_start + 330
    fixture_raw, pins_raw = FIXTURE.read_bytes(), PINS.read_bytes()
    fixture, pins = json.loads(fixture_raw), json.loads(pins_raw)
    arch = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    pin = pins["architectures"][arch]
    scanner_pins_raw = Path(".github/scanner-versions.json").read_bytes()
    scanner_pin = json.loads(scanner_pins_raw)["grype"]
    assert scanner_pin["version"] == pin["version"] == "0.119.0"
    assert scanner_pin["linux_" + arch + "_sha256"] == pin["archive_sha256"]
    installed, checkout = Path(contract.__file__).resolve().parent, Path("sourcebastion/inventory").resolve()
    assert not installed.is_relative_to(Path.cwd().resolve())
    source_modules = modules(checkout, admission_deadline)
    assert modules(installed, admission_deadline) == source_modules
    binary = file_binding(BINARY, maximum=128 * 1024 * 1024, deadline=admission_deadline)
    assert binary["sha256"] == pin["binary_sha256"] and binary["bytes"] == pin["binary_bytes"]
    with tempfile.TemporaryDirectory(prefix="native-real-grype-") as temporary:
        private = Path(temporary)
        for name in ("cwd", "home", "config-home"):
            (private / name).mkdir(mode=0o700)
        config_path = private / "grype.yaml"
        config_raw = b"check-for-app-update: false\ndb:\n  auto-update: false\n  cache-dir: /advisories\n  validate-age: true\n  max-allowed-built-age: 120h\n  validate-by-hash-on-start: true\n"
        with config_path.open("xb") as handle:
            handle.write(config_raw)
        config_path.chmod(0o600)
        environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(private / "home"),
            "XDG_CONFIG_HOME": str(private / "config-home"),
            "LC_ALL": "C",
            "GRYPE_DB_CACHE_DIR": str(ADVISORIES),
            "GRYPE_DB_AUTO_UPDATE": "false",
            "GRYPE_CHECK_FOR_APP_UPDATE": "false",
            "GRYPE_DB_VALIDATE_AGE": "true",
            "GRYPE_DB_MAX_ALLOWED_BUILT_AGE": "120h",
            "GRYPE_DB_VALIDATE_BY_HASH_ON_START": "true",
        }
        config_identity = {
            "yaml_sha256": sha(config_raw),
            "environment": environment,
            "source_policy": "explicit-sbom-only",
        }
        (OUTPUT / "consumer-config.json").write_bytes(render(config_identity))
        (OUTPUT / "grype.yaml").write_bytes(config_raw)
        prefix = [str(BINARY), "--config", str(config_path)]
        for name, args in (("version", ["version", "-o", "json"]), ("status", ["db", "status", "-o", "json"])):
            capture(
                prefix + args,
                environment=environment,
                cwd=private / "cwd",
                stdout=OUTPUT / (name + ".json"),
                stderr=OUTPUT / (name + ".stderr"),
                deadline=admission_deadline,
                check=lambda: guard(admission_deadline),
            )
        version = json.loads((OUTPUT / "version.json").read_bytes())
        status = json.loads((OUTPUT / "status.json").read_bytes())
        assert version["version"] == pin["version"] and status["valid"] is True
        advisory = advisory_binding(ADVISORIES, admission_deadline)
        snapshot = json.loads((ADVISORIES / "snapshot.json").read_bytes())
        assert snapshot["database"]["valid"] is True
        assert all(snapshot["database"][key] == status[key] for key in ("built", "schemaVersion"))
        advisory_content = {
            path: {"sha256": row["sha256"], "bytes": row["bytes"]} for path, row in advisory["files"].items()
        }
        (OUTPUT / "advisory-binding.json").write_bytes(render({"binding": advisory, "status": status}))
        consumer = Consumer(
            binary_sha256=binary["sha256"],
            version=pin["version"],
            config_sha256=sha(render(config_identity)),
            advisory_snapshot_sha256=sha(render(advisory_content)),
            advisory_schema=status["schemaVersion"],
            advisory_built=status["built"],
        )
        config = DiscoveryConfig(mappings=tuple(tuple(row) for row in fixture["discovery_config"]["mappings"]))
        producer = Producer(
            name="native-real-grype-finite",
            version="1",
            code_sha256=sha(render(source_modules)),
            registry_sha256=REGISTRY_SHA256,
            config_sha256=config.sha256,
        )
        scan_start = time.monotonic()
        with Source("/fixture") as source:
            expected_files = {row["path"]: row for row in fixture["files"]}
            entries = tuple(source.discover())
            assert all(entry.kind in {"file", "directory"} for entry in entries)
            assert {entry.path for entry in entries if entry.kind == "file"} == expected_files.keys()
            for path, row in expected_files.items():
                data = source.read(path)
                assert data.content == row["utf8"].encode() and data.sha256 == row["sha256"]
            value = compose_source(source, source_sha256=sha(render(expected_files)), producer=producer, config=config)
            before = canonical_bytes(value)
            (OUTPUT / "inventory.json").write_bytes(before)
            assert (
                len(value.occurrences) == 3
                and not value.relationships
                and not value.roots
                and not value.installed_environments
            )
            by_path = {row.source.path: row for row in value.occurrences}
            selected = set()
            for wanted in fixture["expected"]["selected"]:
                row = by_path[wanted["path"]]
                assert (
                    row.source.locator == "line:1"
                    and row.source.source_sha256 == expected_files[wanted["path"]]["sha256"]
                )
                assert row.name == wanted["name"] and row.selected_version == wanted["version"]
                assert row.purl == "pkg:pypi/requests@2.19.1"
                assert row.activation == wanted["activation"] and row.marker == wanted.get("marker")
                assert (
                    row.root_id is row.installed_environment_id is None
                    and row.directness == "unknown"
                    and not row.scopes
                )
                selected.add(row.id)
            unselected = by_path[fixture["expected"]["unselected"][0]["path"]]
            assert unselected.selected_version is None and unselected.purl == "pkg:pypi/requests"
            assert (
                unselected.source.locator == "line:1"
                and unselected.source.source_sha256 == expected_files[unselected.source.path]["sha256"]
            )
            wanted_range = fixture["expected"]["unselected"][0]
            assert (
                unselected.name == wanted_range["name"] and unselected.declared_range == wanted_range["declared_range"]
            )
            assert unselected.activation == "active" and unselected.marker is None
            assert (
                unselected.root_id is unselected.installed_environment_id is None and unselected.directness == "unknown"
            )
            assert (
                len(selected) == 2
                and len({by_path[w["path"]].analysis_scope_id for w in fixture["expected"]["selected"]}) == 2
            )
            artifact = export(value, deadline=source.deadline, check=source.check)
            document = json.loads(artifact.content)
            assert {row["bom-ref"] for row in document["components"]} == selected
            assert len(document["components"]) == 2 and not document.get("dependencies")
            sbom_path = OUTPUT / "inventory.cdx.json"
            sbom_path.write_bytes(artifact.content)
            execution = capture(
                prefix + ["sbom:" + str(sbom_path), "-o", "json", "-q"],
                environment=environment,
                cwd=private / "cwd",
                stdout=OUTPUT / "grype.json",
                stderr=OUTPUT / "grype.stderr",
                deadline=source.deadline,
                check=source.check,
            )
            raw = (OUTPUT / "grype.json").read_bytes()
            result = recover(value, artifact, raw, consumer=consumer, deadline=source.deadline, check=source.check)
            assert result.original_output == raw and result.output_sha256 == sha(raw)
            matches = json.loads(raw)["matches"]
            aliases = {(row["id"], row["namespace"]) for row in fixture["expected"]["advisory_aliases"]}
            assert {
                binding.occurrence_id for binding in result.matches if known_advisory(matches[binding.ordinal], aliases)
            } == selected
            assert all(binding.match_sha256 == sha(render(matches[binding.ordinal])) for binding in result.matches)
            assert all(
                json.loads(context) == by_path[row["path"]].model_dump(mode="json")
                for identifier, context in result.occurrence_contexts
                for row in fixture["expected"]["selected"]
                if identifier == by_path[row["path"]].id
            )
            assert {identifier for identifier, _ in result.occurrence_contexts} == selected
            source.validate()
            assert canonical_bytes(value) == before and value.stages.matching == value.stages.export == "not-run"
            assert sbom_path.read_bytes() == artifact.content and config_path.read_bytes() == config_raw
            assert file_binding(BINARY, maximum=128 * 1024 * 1024, deadline=source.deadline) == binary
            assert advisory_binding(ADVISORIES, source.deadline) == advisory
            assert modules(installed, source.deadline) == modules(checkout, source.deadline) == source_modules
            assert FIXTURE.read_bytes() == fixture_raw and PINS.read_bytes() == pins_raw
            assert Path(".github/scanner-versions.json").read_bytes() == scanner_pins_raw
            source.validate()
            source.check()
            receipt = {
                "schema_version": "sourcebastion.real-grype-native-proof/1",
                "status": "native-real-grype-finite-passed",
                "python": platform.python_version(),
                "architecture": platform.machine(),
                "uid": os.getuid(),
                "gid": os.getgid(),
                "fixture_sha256": sha(fixture_raw),
                "binary_pins_sha256": sha(pins_raw),
                "source_modules": source_modules,
                "discovery_config_sha256": config.sha256,
                "consumer": consumer.model_dump(mode="json"),
                "admission_wall_seconds": scan_start - admission_start,
                "advisory_byte_ceiling": ADVISORY_BYTES,
                "source_wall_seconds": time.monotonic() - scan_start,
                "source_deadline_seconds": source.limits.wall_seconds,
                "execution": execution,
                "inventory_sha256": sha(before),
                "sbom_sha256": artifact.sha256,
                "grype_stdout_sha256": sha(raw),
                "recovery_identity_sha256": result.identity_sha256,
                "selected_ids": sorted(selected),
                "unselected_id": unselected.id,
                "matches": len(result.matches),
                "known_advisory_on_each_selected_id": True,
                "recovered_contexts": {
                    identifier: json.loads(context) for identifier, context in result.occurrence_contexts
                },
                "scope": "One source-authored native real consumer fixture; readonly/offline Docker policy recorded by outer CI. No aggregate CPU-time/kernel trace, persistent independent custody, whole S04/S06, release or deployment acceptance. Findings cross-architecture comparable only with equal advisory snapshot identity.",
            }
        (OUTPUT / "receipt.json").write_bytes(render(receipt))
        print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    try:
        verify()
    except Exception as error:
        failure = {"status": "native-real-grype-failed", "reason": type(error).__name__}
        if OUTPUT.is_dir():
            (OUTPUT / "failure.json").write_bytes(render(failure))
        print(json.dumps(failure, sort_keys=True))
        raise
