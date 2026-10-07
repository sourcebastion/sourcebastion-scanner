"""Trusted preparation only: build the pinned restricted evidence provider.

Network is allowed for verified toolchain/module downloads. No customer checkout
is passed here. Cataloging itself uses the separate offline process boundary.
"""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import tarfile
from urllib.request import urlopen


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def prepare(destination):
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if architecture is None or platform.system() != "Linux":
        raise ValueError("native-linux-required")
    source = Path(__file__).resolve().parents[1] / "cmd/inventory-provider"
    names = ("go.mod", "go.sum", "main.go", "main_test.go", "toolchain.json")
    before = {name: digest(source / name) for name in names}
    pins = json.loads((source / "toolchain.json").read_text())
    destination.mkdir(parents=True, exist_ok=False)
    archive_path = destination / "go.tar.gz"
    url = f"https://go.dev/dl/go{pins['version']}.linux-{architecture}.tar.gz"
    with urlopen(url, timeout=60) as response, archive_path.open("xb") as output:
        size = 0
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > 256 * 1024 * 1024:
                raise ValueError("toolchain-download-budget-exceeded")
            output.write(chunk)
    if digest(archive_path) != pins[f"linux_{architecture}_sha256"]:
        raise ValueError("toolchain-archive-digest-mismatch")
    with tarfile.open(archive_path) as archive:
        archive.extractall(destination, filter="data")
    go = destination / "go/bin/go"
    temporary = destination / "tmp"
    temporary.mkdir()
    env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "TZ": "UTC",
        "GOTOOLCHAIN": "local",
        "GOWORK": "off",
        "GOENV": "off",
        "GOFLAGS": "-mod=readonly",
        "GOCACHE": str(destination / "cache"),
        "GOPATH": str(destination / "modules"),
        "GOTMPDIR": str(temporary),
        "GOMAXPROCS": "2",
        "GOOS": "linux",
        "GOARCH": architecture,
        "CGO_ENABLED": "0",
        "GOAMD64": "v1",
        "GOARM64": "v8.0",
        "GOSUMDB": "sum.golang.org",
        "GOPROXY": "https://proxy.golang.org",
    }
    binary = destination / "sourcebastion-inventory-provider"
    commands = [
        ("download", ["mod", "download"]),
        ("verify", ["mod", "verify"]),
        ("tests", ["test", "-trimpath", "-count=1", "-p", "2", "-timeout", "90s", "-json", "./..."]),
        ("build", ["build", "-trimpath", "-buildvcs=false", "-p", "2", "-o", str(binary), "."]),
        ("buildinfo", ["version", "-m", str(binary)]),
        ("modules", ["list", "-m", "-json", "all"]),
    ]
    logs = {}
    for name, arguments in commands:
        if name != "download":
            env.update(GOPROXY="off", GOSUMDB="off")
        with (
            (destination / f"{name}.stdout").open("xb") as stdout,
            (destination / f"{name}.stderr").open("xb") as stderr,
        ):
            subprocess.run(
                [str(go), *arguments], cwd=source, env=env, stdout=stdout, stderr=stderr, timeout=900, check=True
            )
        if {name: digest(source / name) for name in names} != before:
            raise ValueError("provider-source-changed-during-preparation")
        logs[name] = {suffix: digest(destination / f"{name}.{suffix}") for suffix in ("stdout", "stderr")}
    result = {
        "schema_version": "sourcebastion.provider-preparation/1",
        "status": "trusted-preparation-only",
        "architecture": architecture,
        "go_version": pins["version"],
        "go_archive_sha256": digest(archive_path),
        "go_executable_sha256": digest(go),
        "source_files": before,
        "binary_sha256": digest(binary),
        "binary_bytes": binary.stat().st_size,
        "cgo_enabled": "0",
        "logs": logs,
    }
    (destination / "manifest.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    prepare(parser.parse_args().output.resolve())
