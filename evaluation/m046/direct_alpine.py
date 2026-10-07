"""Native seven-wheel Alpine feasibility on one immutable scanner overlay."""

import argparse
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import uuid
import zipfile

from . import benchmark
from .direct_alpine_probe import code_member
from .direct_alpine_guard import child_limits
from .direct_audit import audit
from .direct_prepare import VERSIONS
from .run import digest, snapshot
from .static_runtime import FRONTEND, context_identity, normalize_context
from .syft_control_audit import decode, hash_records
from .syft_control_benchmark import checkpoint

MAX_OUTPUT = 64 * 1024**2
FILES = {"a/requirements.txt": "pip==26.0.1\n", "b/requirements.txt": "pip==26.0.1\n"}


def source_identity():
    root = Path(__file__).resolve().parent
    return {
        str(path.relative_to(root)): digest(path)
        for path in sorted(
            [
                *root.glob("*.py"),
                *root.glob("requirements-*.txt"),
                root / "runtime-image-pins.json",
                *root.joinpath("schemas").iterdir(),
            ]
        )
        if path.is_file()
    }


def checked(command, output, name, timeout=300):
    parent = os.getpid()
    with (output / (name + ".stdout")).open("xb") as stdout, (output / (name + ".stderr")).open("xb") as stderr:
        subprocess.run(
            command, stdout=stdout, stderr=stderr, check=True, timeout=timeout, preexec_fn=lambda: child_limits(parent)
        )


def inspect(name, output, label):
    checked([*benchmark.DOCKER, "inspect", name], output, label, 30)
    path = output / (label + ".stdout")
    if path.stat().st_size > 1024**2:
        raise ValueError("Docker inspection exceeds separate metadata bound")
    return decode(path.read_bytes())[0]


def context(output, reference, architecture):
    root = Path(__file__).resolve().parent
    target = output / "context"
    target.mkdir()
    app = target / "frontend"
    frontend = app / "evaluation/m046"
    frontend.mkdir(parents=True)
    for name in (*FRONTEND, "cyclonedx_export.py"):
        shutil.copyfile(root / name, frontend / name)
    shutil.copytree(root / "schemas", frontend / "schemas")
    for name in ("direct_job.py", "direct_alpine_probe.py"):
        shutil.copyfile(root / name, app / name)
    provenance = {
        "producer": "m046-direct-alpine-feasibility",
        "code_sha256": digest(root / "direct_alpine_probe.py"),
        "registry_sha256": digest(root / "static_inventory.py"),
        "config_sha256": digest(root / "direct_job.py"),
        "environment_policy": "unknown-activation; no target environment resolution",
    }
    (app / "provenance.json").write_text(json.dumps(provenance, sort_keys=True) + "\n")
    requirements = target / "requirements.txt"
    requirements.write_bytes(
        (root / "requirements-static.txt").read_bytes() + b"\n" + (root / "requirements-export.txt").read_bytes()
    )
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
            "--platform",
            "musllinux_1_2_" + {"amd64": "x86_64", "arm64": "aarch64"}[architecture],
            "--python-version",
            "314",
            "--implementation",
            "cp",
            "--abi",
            "cp314",
            "--dest",
            str(wheels),
            "-r",
            str(requirements),
        ],
        output,
        "wheels",
    )
    packages = {}
    for wheel in sorted(wheels.iterdir()):
        with zipfile.ZipFile(wheel) as archive:
            metadata = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
            if len(metadata) != 1:
                raise ValueError("ambiguous prepared wheel metadata")
            message = BytesParser().parsebytes(archive.read(metadata[0]))
            name = message["Name"].lower().replace("_", "-")
            if name in packages or message["Version"] != VERSIONS.get(name):
                raise ValueError("unexpected prepared wheel")
            packages[name] = {
                "version": message["Version"],
                "sources": {
                    name: hashlib.sha256(archive.read(name)).hexdigest()
                    for name in archive.namelist()
                    if code_member(Path(name))
                },
            }
    if set(packages) != set(VERSIONS) or any(not row["sources"] for row in packages.values()):
        raise ValueError("incomplete seven-wheel closure")
    (target / "Dockerfile").write_text(
        f"FROM {reference} AS prepared\nUSER root\n"
        "COPY wheels /tmp/m046-wheels\nCOPY requirements.txt /tmp/m046-requirements.txt\n"
        "RUN --network=none python3 -m venv --without-pip /opt/m046/venv && "
        "python3 -m pip --python /opt/m046/venv install --no-compile --no-index --no-deps "
        "--only-binary=:all: --require-hashes --find-links=/tmp/m046-wheels -r /tmp/m046-requirements.txt\n"
        "COPY frontend /opt/m046/frontend\n"
        f"FROM {reference}\nCOPY --from=prepared /opt/m046 /opt/m046\n"
    )
    normalize_context(target)
    expected = {str(path.relative_to(app)): digest(path) for path in sorted(app.rglob("*")) if path.is_file()}
    return target, packages, expected


def verify_probe(observed, packages, frontend, architecture, oracle):
    if (
        observed.get("status") != "finite-import-export-only"
        or observed.get("python") != "3.14.8"
        or observed.get("architecture") != {"amd64": "x86_64", "arm64": "aarch64"}[architecture]
        or observed.get("executable") != "/opt/m046/venv/bin/python"
        or observed.get("prefix") != "/opt/m046/venv"
        or observed.get("isolated") != 1
        or observed.get("uid") != 65534
        or observed.get("gid") != 65534
        or "ID=alpine\n" not in observed.get("os_release", "")
        or "VERSION_ID=3.23." not in observed.get("os_release", "")
        or observed.get("packages") != packages
        or observed.get("frontend") != frontend
        or observed.get("full_contract_qualified") is not False
    ):
        raise ValueError("actual Alpine runtime identity mismatch")
    loaded = observed.get("loaded_libraries", {})
    native = packages["rpds-py"]["sources"]
    expected_native = {name: sha for name, sha in native.items() if ".so" in Path(name).name}
    if len(expected_native) != 2 or not any(".so.1" in name for name in expected_native):
        raise ValueError("reviewed rpds vendor closure changed")
    for name, sha in expected_native.items():
        path = "/opt/m046/venv/lib/python3.14/site-packages/" + name
        if loaded.get(path) != sha:
            raise ValueError("wheel native library was not loaded with expected identity")
    return audit(observed["sbom"], oracle, "direct-cyclonedx")


def verify_container(container, image_id, source):
    host, config = container["HostConfig"], container["Config"]
    mounts = container["Mounts"]
    if (
        container["Image"] != image_id
        or config["User"] != "65534:65534"
        or config["Entrypoint"] != ["/opt/m046/venv/bin/python"]
        or config["Cmd"] != ["-I", "-B", "/opt/m046/frontend/direct_alpine_probe.py"]
        or host["NetworkMode"] != "none"
        or host["ReadonlyRootfs"] is not True
        or host["Privileged"] is not False
        or host["Memory"] != 2 * 1024**3
        or host["MemorySwap"] != 2 * 1024**3
        or host["NanoCpus"] != 2_000_000_000
        or host["PidsLimit"] != 32
        or set(host["CapDrop"] or []) != {"ALL"}
        or host.get("CapAdd")
        or host["SecurityOpt"] != ["no-new-privileges"]
        or len(mounts) != 1
        or mounts[0]["Type"] != "bind"
        or mounts[0]["Source"] != str(source.resolve())
        or mounts[0]["Destination"] != "/source"
        or mounts[0]["RW"] is not False
    ):
        raise ValueError("actual Alpine container boundary mismatch")


def run(output):
    identity = source_identity()
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    root = Path(__file__).resolve().parent
    pins_path = root / "runtime-image-pins.json"
    pins = decode(pins_path.read_bytes())
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "status": "preparing",
        "architecture": architecture,
        "candidate_sources": identity,
        "baseline_reference": pins["reference"],
        "plan": [{"fixture": "two-root-pip"}],
        "records": [],
        "scope": "finite native import/export and image feasibility; no aggregate resource, trace, engine or release acceptance",
        "license_limits": "vendor libgcc origin/notices/source and complete distribution closure remain S06 obligations",
    }
    checkpoint(output, report)
    try:
        checked([*benchmark.DOCKER, "version", "--format", "{{json .}}"], output, "docker-version")
        checked([*benchmark.DOCKER, "buildx", "version"], output, "buildx-version")
        checked([*benchmark.DOCKER, "buildx", "inspect", "--bootstrap"], output, "builder-inspect")
        target, packages, frontend = context(output, pins["reference"], architecture)
        report["context_files"] = context_identity(target)
        report["expected_packages"], report["expected_frontend"] = packages, frontend
        if source_identity() != identity:
            raise ValueError("Alpine preparation source changed")
        checkpoint(output, report)
        tag = "m046-direct-alpine:" + uuid.uuid4().hex
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
        loaded = inspect(tag, output, "loaded-inspect")
        if source_identity() != identity or context_identity(target) != report["context_files"]:
            raise ValueError("Alpine build source or context changed")
        report["loaded_image"] = loaded
        (output / "loaded-image.json").write_text(json.dumps(loaded) + "\n")
        checked(
            [
                sys.executable,
                "-I",
                "-B",
                str(root / "runtime_oci.py"),
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
        report["image_cost"] = decode((output / "oci-audit.stdout").read_bytes())
        if not report["image_cost"]["fits_proposed_limit"]:
            raise ValueError("Alpine overlay exceeds proposed added-image ceiling")
        report["oci_sha256"] = digest(oci)
        (output / "runtime.oci.tar.sha256").write_text(report["oci_sha256"] + "  runtime.oci.tar\n")
        source = output / "source"
        for name, content in FILES.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        normalize_context(source)
        before = snapshot(source)
        oracle = {
            "spec": {"kind": "pins", "count": 2},
            "files": {
                name: {"sha256": hashlib.sha256(content.encode()).hexdigest()} for name, content in FILES.items()
            },
            "expected": {
                "identities": 1,
                "occurrences": 2,
                "identities_sha256": hash_records({"pypi:pip@26.0.1"}),
                "occurrences_sha256": hash_records([("a", "pypi:pip@26.0.1"), ("b", "pypi:pip@26.0.1")]),
            },
        }
        (output / "source-snapshot.json").write_text(json.dumps(before, sort_keys=True) + "\n")
        (output / "oracle.json").write_text(json.dumps(oracle, sort_keys=True) + "\n")
        name = "m046-direct-alpine-" + uuid.uuid4().hex
        record = {
            "fixture": "two-root-pip",
            "attempt_status": "started",
            "container_name": name,
            "cidfile": str(output / "container.id"),
        }
        report["records"].append(record)
        checkpoint(output, report)
        read_fd, write_fd = os.pipe()
        with (
            (output / "watchdog.stdout").open("xb") as guard_stdout,
            (output / "watchdog.stderr").open("xb") as guard_stderr,
        ):
            watchdog = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(root / "direct_alpine_guard.py"),
                    "--fd",
                    str(read_fd),
                    "--name",
                    name,
                    "--output",
                    str(output / "watchdog.json"),
                    "--cidfile",
                    str(output / "container.id"),
                ],
                pass_fds=(read_fd,),
                start_new_session=True,
                stdout=guard_stdout,
                stderr=guard_stderr,
            )
        os.close(read_fd)
        try:
            checked(
                [
                    *benchmark.DOCKER,
                    "create",
                    "--name",
                    name,
                    "--cidfile",
                    str(output / "container.id"),
                    "--no-healthcheck",
                    "--network",
                    "none",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--user",
                    "65534:65534",
                    "--cpus",
                    "2",
                    "--memory",
                    str(2 * 1024**3),
                    "--memory-swap",
                    str(2 * 1024**3),
                    "--pids-limit",
                    "32",
                    "--mount",
                    f"type=bind,src={source.resolve()},dst=/source,readonly",
                    "--entrypoint",
                    "/opt/m046/venv/bin/python",
                    loaded["Id"],
                    "-I",
                    "-B",
                    "/opt/m046/frontend/direct_alpine_probe.py",
                ],
                output,
                "container-create",
                30,
            )
            container = inspect(name, output, "container-inspect")
            container_id = (output / "container.id").read_text().strip()
            if len(container_id) != 64 or container["Id"] != container_id:
                raise ValueError("created container CID differs from inspection")
            record["container_id"] = container_id
            record["inspected_container"] = container
            verify_container(container, loaded["Id"], source)
            checkpoint(output, report)
            checked([*benchmark.DOCKER, "start", "--attach", name], output, "probe", 35)
            ended = inspect(name, output, "ended-inspect")
            record["ended_state"] = ended["State"]
            if ended["State"]["Running"] or ended["State"]["ExitCode"] != 0 or ended["State"]["OOMKilled"]:
                raise ValueError("finite Alpine probe did not exit cleanly")
        finally:
            os.write(write_fd, b"D")
            os.close(write_fd)
            status = watchdog.wait(timeout=15)
            receipt = decode((output / "watchdog.json").read_bytes())
            record["watchdog"] = receipt
            if (
                status != 0
                or receipt["reason"] != "controller-completed"
                or not receipt["cleanup_confirmed"]
                or receipt["container_name"] != name
                or receipt["known_container_ids"] != [record.get("container_id")]
            ):
                raise RuntimeError("Alpine probe cleanup uncertain or independent deadline exceeded")
        if (output / "probe.stdout").stat().st_size > 2 * 1024**2:
            raise ValueError("Alpine probe exceeds separate 2MiB identity/export bound")
        observed = decode((output / "probe.stdout").read_bytes())
        record["audit"] = verify_probe(observed, packages, frontend, architecture, oracle)
        if (
            snapshot(source) != before
            or source_identity() != identity
            or context_identity(target) != report["context_files"]
        ):
            raise ValueError("Alpine source or runtime context changed")
        record.update(attempt_status="completed", raw_sha256=digest(output / "probe.stdout"))
        report["status"] = "completed-finite-alpine-feasibility-only"
        checkpoint(output, report)
    except BaseException as error:
        report.update(status="aborted", abort_error=f"{type(error).__name__}: {error}"[:4096])
        checkpoint(output, report)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    run(parser.parse_args().output.resolve())
