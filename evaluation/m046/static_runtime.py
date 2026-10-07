"""Trusted static overlay preparation and finite-corpus native runtime proof."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import uuid
import zipfile

from . import benchmark
from .corpus import CORPUS
from .run import digest, materialize
from .static_elf import validate
from .syft_control_benchmark import checkpoint
from .syft_native import candidate_source_identity

FRONTEND = (
    "static_cli.py",
    "static_inputs.py",
    "static_inventory.py",
    "static_requirements.py",
    "static_manifests.py",
    "static_manifest_records.py",
    "static_markers.py",
    "static_locks.py",
    "static_lock_records.py",
    "static_python_locks.py",
    "static_python_lock_records.py",
    "static_poetry_constraints.py",
)


def checked(command, directory, name, timeout=300):
    with (directory / (name + ".stdout")).open("wb") as stdout, (directory / (name + ".stderr")).open("wb") as stderr:
        subprocess.run(command, stdout=stdout, stderr=stderr, check=True, timeout=timeout)


def normalize_context(target):
    target.chmod(0o755)
    for path in target.rglob("*"):
        path.chmod(0o755 if path.is_dir() or path.name == "m046-syft" else 0o644)


def context_identity(target):
    return {
        str(path.relative_to(target)): {
            "mode": stat.S_IMODE(path.stat().st_mode),
            "sha256": digest(path) if path.is_file() else None,
        }
        for path in sorted(target.rglob("*"))
    }


def context(binary, output, reference):
    """Only trusted tool payload/wheels enter the build; no scanned sources."""
    root = Path(__file__).resolve().parent
    target = output / "context"
    target.mkdir()
    shutil.copyfile(binary, target / "m046-syft")
    (target / "m046-syft").chmod(0o755)
    shutil.copyfile(root / "requirements-static.txt", target / "requirements.txt")
    shutil.copyfile(root / "runtime_inspect.py", target / "runtime_inspect.py")
    frontend = target / "frontend/evaluation/m046"
    frontend.mkdir(parents=True)
    expected_frontend = {}
    for name in FRONTEND:
        shutil.copyfile(root / name, frontend / name)
        expected_frontend["evaluation/m046/" + name] = digest(frontend / name)
    wheels = target / "wheels"
    wheels.mkdir()
    checked(
        [
            sys.executable,
            "-m",
            "pip",
            "download",
            "--require-hashes",
            "--no-deps",
            "--only-binary=:all:",
            "--dest",
            str(wheels),
            "-r",
            str(target / "requirements.txt"),
        ],
        output,
        "wheels",
    )
    expected_packages = {}
    for name, version, prefix, checksum in (
        ("packaging", "25.0", "packaging", "29572ef2b1f17581046b3a2227d5c611fb25ec70ca1ba8554b24b0e69331a484"),
        ("poetry-core", "2.1.3", "poetry", "2c704f05016698a54ca1d327f46ce2426d72eaca6ff614132c8477c292266771"),
    ):
        wheel = next(path for path in wheels.glob("*.whl") if digest(path) == checksum)
        with zipfile.ZipFile(wheel) as archive:
            sources = {
                path: hashlib.sha256(archive.read(path)).hexdigest()
                for path in archive.namelist()
                if path.startswith(prefix + "/") and path.endswith(".py")
            }
        if not sources:
            raise ValueError("wheel code identity empty")
        expected_packages[name] = {"version": version, "sources": sources}
    if len(list(wheels.iterdir())) != 2:
        raise ValueError("unexpected prepared runtime wheel")
    (target / "Dockerfile").write_text(
        f"FROM {reference} AS prepared\nUSER root\n"
        "COPY wheels /tmp/m046-wheels\nCOPY requirements.txt /tmp/m046-requirements.txt\n"
        "RUN --network=none python3 -m venv --without-pip /opt/m046/venv && "
        "python3 -m pip --python /opt/m046/venv install --no-compile --no-index --no-deps "
        "--only-binary=:all: --require-hashes --find-links=/tmp/m046-wheels -r /tmp/m046-requirements.txt\n"
        "COPY m046-syft /opt/m046/bin/m046-syft\n"
        "COPY frontend /opt/m046/frontend\nCOPY runtime_inspect.py /opt/m046/runtime_inspect.py\n"
        f"FROM {reference}\nCOPY --from=prepared /opt/m046 /opt/m046\n"
    )
    normalize_context(target)
    return target, expected_frontend, expected_packages


def run(binary, manifest_path, output):
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    identity = candidate_source_identity()
    preparation = json.loads(manifest_path.read_text())
    if (
        preparation.get("runtime_profile") != "static"
        or preparation.get("cgo_enabled") != "0"
        or preparation["architecture"] != architecture
        or preparation["candidate_sources"] != identity
        or preparation["binary_sha256"] != digest(binary)
        or preparation["static_elf"] != validate(binary)
    ):
        raise ValueError("static runtime preparation identity mismatch")
    pins_path = Path(__file__).with_name("runtime-image-pins.json")
    pins = json.loads(pins_path.read_text())
    baseline = pins["architectures"][architecture]
    output.mkdir(parents=True, exist_ok=False)
    records = []
    report = {
        "status": "preparing",
        "plan": [{"fixture": row["id"]} for row in CORPUS],
        "planned_attempts": len(CORPUS),
        "records": records,
        "architecture": architecture,
        "candidate_sources": identity,
        "binary_sha256": digest(binary),
        "preparation_sha256": digest(manifest_path),
        "image_pins_sha256": digest(pins_path),
        "baseline_reference": pins["reference"],
        "scope": "finite-corpus ABI/runtime/image-cost only",
        "limitations": "no complete trace/full-wrapper stress/resource-budget/engine/production acceptance",
    }
    checkpoint(output, report)
    try:
        for name, command in (
            ("docker-version", [*benchmark.DOCKER, "version", "--format", "{{json .}}"]),
            ("buildx-version", [*benchmark.DOCKER, "buildx", "version"]),
            ("builder-inspect", [*benchmark.DOCKER, "buildx", "inspect", "--bootstrap"]),
        ):
            checked(command, output, name)
        report["build_tools"] = {
            name: digest(output / (name + ".stdout"))
            for name in ("docker-version", "buildx-version", "builder-inspect")
        }
        builders = benchmark.docker(
            "ps", "--no-trunc", "--filter", "name=buildx_buildkit_", "--format", "{{.ID}}"
        ).splitlines()
        report["builder_images"] = []
        for identifier in builders:
            if len(identifier) != 64 or any(character not in "0123456789abcdef" for character in identifier):
                raise ValueError("invalid inspected builder container")
            container = json.loads(benchmark.docker("inspect", identifier))[0]
            image = json.loads(benchmark.docker("image", "inspect", container["Image"]))[0]
            report["builder_images"].append(
                {
                    "container": identifier,
                    "image_id": image["Id"],
                    "repo_digests": image.get("RepoDigests", []),
                    "architecture": image["Architecture"],
                }
            )
        if not report["builder_images"]:
            raise ValueError("native builder image identity unavailable")
        checkpoint(output, report)
        target, frontend, packages = context(binary, output, pins["reference"])
        report["context_files"] = context_identity(target)
        if candidate_source_identity() != identity:
            raise ValueError("runtime preparation source changed")
        tag = "m046-static-runtime:" + uuid.uuid4().hex
        oci = output / "runtime.oci.tar"
        checked(
            [
                *benchmark.DOCKER,
                "buildx",
                "build",
                "--platform",
                "linux/" + architecture,
                "--provenance=false",
                "--sbom=false",
                "--tag",
                tag,
                "--load",
                "--output",
                f"type=oci,dest={oci},compression=gzip,oci-mediatypes=true",
                str(target),
            ],
            output,
            "image-build",
            900,
        )
        loaded = json.loads(benchmark.docker("image", "inspect", tag))[0]
        if (
            report["context_files"] != context_identity(target)
            or candidate_source_identity() != identity
            or digest(pins_path) != report["image_pins_sha256"]
        ):
            raise ValueError("runtime build context or source changed")
        report["loaded_image"] = loaded
        (output / "loaded-image.json").write_text(json.dumps(loaded) + "\n")
        checked(
            [
                sys.executable,
                "-I",
                "-B",
                str(Path(__file__).with_name("runtime_oci.py")),
                "--archive",
                str(oci),
                "--pins",
                str(pins_path),
                "--architecture",
                architecture,
                "--loaded",
                str(output / "loaded-image.json"),
            ],
            output,
            "oci-audit",
            150,
        )
        report["image_cost"] = json.loads((output / "oci-audit.stdout").read_text())
        report["oci_sha256"] = digest(oci)
        (output / "runtime.oci.tar.sha256").write_text(report["oci_sha256"] + "  runtime.oci.tar\n")
        image_id = loaded["Id"]
        identity_name = "m046-identity-" + uuid.uuid4().hex
        report["identity_container_name"] = identity_name
        checkpoint(output, report)
        try:
            checked(
                [
                    *benchmark.DOCKER,
                    "run",
                    "--rm",
                    "--name",
                    identity_name,
                    "--cidfile",
                    str(output / "identity-container.id"),
                    "--no-healthcheck",
                    "--network",
                    "none",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--memory",
                    "536870912",
                    "--memory-swap",
                    "536870912",
                    "--pids-limit",
                    "32",
                    "--entrypoint",
                    "/opt/m046/venv/bin/python",
                    image_id,
                    "-I",
                    "-B",
                    "/opt/m046/runtime_inspect.py",
                ],
                output,
                "image-identity",
                30,
            )
        finally:
            cleanup = subprocess.run(
                [*benchmark.DOCKER, "rm", "--force", identity_name], capture_output=True, timeout=30
            )
            if cleanup.returncode and ("No such container: " + identity_name) not in cleanup.stderr.decode(
                errors="replace"
            ):
                raise RuntimeError("runtime identity container cleanup uncertain")
        observed = json.loads((output / "image-identity.stdout").read_text())
        if (
            observed["python"] != "3.14.8"
            or observed["architecture"] != platform.machine()
            or observed["executable"] != "/opt/m046/venv/bin/python"
            or observed["prefix"] != "/opt/m046/venv"
            or observed["isolated"] != 1
            or observed["binary_sha256"] != report["binary_sha256"]
            or observed["frontend"] != frontend
            or observed["packages"] != packages
        ):
            raise ValueError("actual image tool/frontend/wheel identity mismatch")
        report["runtime_identity"] = observed
        report["status"] = "running"
        checkpoint(output, report)
        tool = {"binary": str(binary), "sha256": report["binary_sha256"]}
        for fixture in CORPUS:
            if (
                candidate_source_identity() != identity
                or digest(binary) != tool["sha256"]
                or digest(pins_path) != report["image_pins_sha256"]
            ):
                raise ValueError("runtime source or executable changed")
            source = output / "sources" / fixture["id"]
            materialize(fixture, source)
            record = {"fixture": fixture["id"], "attempt_status": "started"}
            records.append(record)
            checkpoint(output, report)
            directory = output / "runs" / fixture["id"]
            measurement = benchmark.measure(
                benchmark.SYFT_RUNTIME_ENGINE, tool, source, directory, "python", runtime_image=image_id
            )
            record["measurement"] = measurement
            checkpoint(output, report)
            if not measurement["resource_sample_valid"]:
                raise ValueError("finite runtime sample failed; raw evidence retained")
            checked(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(Path(__file__).with_name("runtime_audit.py")),
                    "--raw",
                    str(directory / "controller/raw.json"),
                    "--fixture",
                    fixture["id"],
                ],
                directory,
                "audit",
                30,
            )
            record["audit"] = json.loads((directory / "audit.stdout").read_text())
            if (
                candidate_source_identity() != identity
                or digest(binary) != tool["sha256"]
                or digest(pins_path) != report["image_pins_sha256"]
            ):
                record["candidate_identity_valid"] = False
                raise ValueError("runtime source or executable changed during attempt")
            record["candidate_identity_valid"] = True
            record["attempt_status"] = "completed"
            checkpoint(output, report)
            print(f"{fixture['id']}: actual static Alpine runtime agrees", flush=True)
        report["status"] = "completed-finite-runtime-only"
        checkpoint(output, report)
    except BaseException as error:
        report["status"] = "aborted"
        report["abort_error"] = f"{type(error).__name__}: {error}"[:4096]
        if records and records[-1]["attempt_status"] != "completed":
            records[-1]["attempt_status"] = "aborted"
        checkpoint(output, report)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.binary.resolve(), args.manifest.resolve(), args.output.resolve())


if __name__ == "__main__":
    main()
