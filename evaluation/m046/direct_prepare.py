"""Prepare trusted, hash-pinned direct-candidate code; never a source scan."""

import argparse
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import zipfile

from .run import digest, tree_digest
from .static_runtime import FRONTEND
from .syft_native import candidate_source_identity

VERSIONS = {
    "packaging": "25.0",
    "poetry-core": "2.1.3",
    "jsonschema": "4.26.0",
    "referencing": "0.37.0",
    "attrs": "26.1.0",
    "rpds-py": "2026.6.3",
    "jsonschema-specifications": "2025.9.1",
}


def source_identity():
    root = Path(__file__).resolve().parent
    return {
        "candidate": candidate_source_identity(),
        "export_inputs": {
            str(path.relative_to(root)): digest(path)
            for path in sorted([root / "requirements-export.txt", *(root / "schemas").iterdir()])
            if path.is_file()
        },
    }


def prepare(output):
    root = Path(__file__).resolve().parent
    identity = source_identity()
    output.mkdir(parents=True, exist_ok=False)
    app, wheels = output / "app", output / "wheels"
    frontend = app / "evaluation/m046"
    frontend.mkdir(parents=True)
    wheels.mkdir()
    sources = {}
    for name in (*FRONTEND, "cyclonedx_export.py"):
        shutil.copyfile(root / name, frontend / name)
        sources["evaluation/m046/" + name] = digest(root / name)
    shutil.copytree(root / "schemas", frontend / "schemas")
    shutil.copyfile(root / "direct_job.py", app / "direct_job.py")
    sources["direct_job.py"] = digest(root / "direct_job.py")
    provenance = {
        "producer": "m046-direct-resource-diagnostic",
        "code_sha256": tree_digest(app),
        "registry_sha256": digest(root / "static_inventory.py"),
        "config_sha256": digest(root / "direct_job.py"),
        "environment_policy": "unknown-activation; no target environment resolution",
    }
    (app / "provenance.json").write_text(json.dumps(provenance, sort_keys=True) + "\n")
    requirements = [str(root / name) for name in ("requirements-static.txt", "requirements-export.txt")]
    common = ["--require-hashes", "--no-deps", "--only-binary=:all:"]
    for name, command in (
        (
            "download",
            [
                sys.executable,
                "-m",
                "pip",
                "download",
                *common,
                "--dest",
                str(wheels),
                *sum((["-r", path] for path in requirements), []),
            ],
        ),
        (
            "install",
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                *common,
                "--no-compile",
                "--no-index",
                "--find-links",
                str(wheels),
                "--target",
                str(app),
                *sum((["-r", path] for path in requirements), []),
            ],
        ),
    ):
        with (output / (name + ".stdout")).open("wb") as stdout, (output / (name + ".stderr")).open("wb") as stderr:
            subprocess.run(command, check=True, stdout=stdout, stderr=stderr, timeout=300)
        if source_identity() != identity:
            raise ValueError("direct preparation source changed")
    packages = {}
    for wheel in sorted(wheels.iterdir()):
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
            metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
            if len(metadata_names) != 1:
                raise ValueError("unexpected wheel metadata")
            metadata = BytesParser().parsebytes(archive.read(metadata_names[0]))
            name = metadata["Name"].lower().replace("_", "-")
            if name in packages or metadata["Version"] != VERSIONS.get(name):
                raise ValueError("unexpected prepared wheel identity")
            packages[name] = {
                "version": metadata["Version"],
                "sources": {
                    path: hashlib.sha256(archive.read(path)).hexdigest()
                    for path in names
                    if Path(path).suffix in {".py", ".so"}
                },
            }
    if set(packages) != set(VERSIONS) or any(not row["sources"] for row in packages.values()):
        raise ValueError("incomplete direct wheel code identity")
    for path in [app, *app.rglob("*")]:
        if path.is_symlink():
            raise ValueError("unexpected link in prepared direct tree")
        path.chmod(0o755 if path.is_dir() else 0o644)
    # The installed RECORD entries must locate exactly the prepared code.
    manifest = {
        "status": "trusted-direct-evaluation-preparation",
        "architecture": {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()],
        "python_version": platform.python_version(),
        "candidate_sources": identity,
        "app": str(app.resolve()),
        "app_sha256": tree_digest(app),
        "copied_sources": sources,
        "wheels": {path.name: digest(path) for path in sorted(wheels.iterdir())},
        "requirements": {Path(path).name: digest(path) for path in requirements},
        "expected_versions": VERSIONS,
        "expected_packages": packages,
        "provenance": provenance,
        "limits": "bookworm resource comparison only; no Alpine packaging/license/engine acceptance",
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.output.resolve())


if __name__ == "__main__":
    main()
