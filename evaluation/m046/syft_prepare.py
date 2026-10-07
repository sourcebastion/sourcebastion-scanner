"""Hash-pinned Go preparation for the M046 Syft library experiment; network allowed."""

import argparse
import json
from pathlib import Path
import platform
import subprocess
import sys
import tarfile

from .prepare import build_environment, download
from .run import digest
from .syft_native import candidate_source_identity
from .static_elf import validate as validate_static_elf


def prepare(destination, static=False):
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if architecture is None or platform.system() != "Linux":
        raise ValueError("native-linux-required")
    destination.mkdir(parents=True, exist_ok=False)
    pins = json.loads(Path(__file__).with_name("tools.json").read_text())["tools"]["scalibr"]
    archive_path = destination / "go.tar.gz"
    download(
        f"https://go.dev/dl/go{pins['go_version']}.linux-{architecture}.tar.gz",
        archive_path,
        pins[f"go_{architecture}_archive_sha256"],
    )
    with tarfile.open(archive_path) as archive:
        archive.extractall(destination, filter="data")
    go = destination / "go/bin/go"
    source = Path(__file__).with_name("syft_extension").resolve()
    modules_before = {name: digest(source / name) for name in ("go.mod", "go.sum")}
    sources_before = candidate_source_identity()
    env = build_environment(destination, architecture)
    if static:
        env["CGO_ENABLED"] = "0"
    env["GOMAXPROCS"] = "2"
    env["GOTMPDIR"] = str(destination / "tmp")
    env["M046_FRONTEND_PYTHON"] = sys.executable
    Path(env["GOTMPDIR"]).mkdir()
    binary = destination / "m046-syft"
    commands = [
        ("download", [str(go), "mod", "download"]),
        ("verify", [str(go), "mod", "verify"]),
        ("tests", [str(go), "test", "-trimpath", "-count=1", "-p", "2", "-json", "./..."]),
        ("build", [str(go), "build", "-p", "2", "-trimpath", "-o", str(binary), "."]),
        ("buildinfo", [str(go), "version", "-m", str(binary)]),
        ("modules", [str(go), "list", "-m", "-json", "all"]),
    ]
    for name, command in commands:
        with (
            (destination / f"{name}.stdout").open("wb") as stdout,
            (destination / f"{name}.stderr").open("wb") as stderr,
        ):
            subprocess.run(command, cwd=source, env=env, stdout=stdout, stderr=stderr, timeout=900, check=True)
        if {name: digest(source / name) for name in modules_before} != modules_before:
            raise ValueError("syft-module-pins-changed-during-preparation")
        if candidate_source_identity() != sources_before:
            raise ValueError("syft-source-changed-during-preparation")
    manifest = {
        "status": "trusted-preparation-only",
        "architecture": architecture,
        "runtime_profile": "static" if static else "glibc-evaluator",
        "cgo_enabled": env["CGO_ENABLED"],
        "static_elf": validate_static_elf(binary) if static else None,
        "go_version": pins["go_version"],
        "go_archive_sha256": digest(archive_path),
        "go_executable_sha256": digest(go),
        "binary_sha256": digest(binary),
        "binary_bytes": binary.stat().st_size,
        "modules": modules_before,
        "candidate_sources": sources_before,
        "effective_build_environment": env,
        "buildinfo_sha256": digest(destination / "buildinfo.stdout"),
        "module_graph_sha256": digest(destination / "modules.stdout"),
        "tests_sha256": digest(destination / "tests.stdout"),
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--static", action="store_true", help="separate CGO-disabled runtime experiment")
    args = parser.parse_args()
    prepare(args.output.resolve(), static=args.static)


if __name__ == "__main__":
    main()
