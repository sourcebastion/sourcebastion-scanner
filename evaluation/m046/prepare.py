"""Prepare verified native evaluation tools; network allowed only in this phase."""

import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
from urllib.request import urlopen

from .run import digest, snapshot, tree_digest


def download(url, destination, sha256):
    with urlopen(url, timeout=60) as response, destination.open("xb") as output:
        while chunk := response.read(1024 * 1024):
            output.write(chunk)
    if digest(destination) != sha256:
        raise ValueError(f"download SHA256 mismatch: {destination.name}")


def prepare(destination):
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if architecture is None or platform.system() != "Linux":
        raise ValueError("native Linux AMD64/ARM64 required")
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    pins_path = Path(__file__).with_name("tools.json")
    pins = json.loads(pins_path.read_text())["tools"]
    manifest = {"schema_version": 1, "architecture": architecture, "pins_sha256": digest(pins_path), "tools": {}}
    syft = pins["syft"]
    syft_archive = destination / "syft.tar.gz"
    download(
        f"https://github.com/anchore/syft/releases/download/v{syft['version']}/syft_{syft['version']}_linux_{architecture}.tar.gz",
        syft_archive,
        syft[f"{architecture}_archive_sha256"],
    )
    with tarfile.open(syft_archive) as archive:
        archive.extract("syft", destination, filter="data")
    syft_binary = destination / "syft"
    manifest["tools"]["syft"] = {
        "binary": str(syft_binary),
        "sha256": digest(syft_binary),
        "archive_sha256": digest(syft_archive),
        "binary_bytes": syft_binary.stat().st_size,
    }
    cdxgen = pins["cdxgen"]
    standalone = destination / "cdxgen"
    download(
        f"https://github.com/cdxgen/cdxgen/releases/download/v{cdxgen['version']}/cdxgen-linux-{architecture}",
        standalone,
        cdxgen[f"{architecture}_binary_sha256"],
    )
    standalone.chmod(0o755)
    extraction = destination / "prepared"
    extraction.mkdir()
    # Caxa uses the OS temporary directory. Isolate it before unbundling; never
    # select a previously prepared app from the shared /tmp/caxa cache.
    result = subprocess.run(
        [str(standalone), "--version"],
        check=True,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TMPDIR": str(extraction)},
        timeout=120,
    )
    entrypoints = list(extraction.rglob("bin/cdxgen.js"))
    if len(entrypoints) != 1:
        raise ValueError("expected one freshly extracted cdxgen entrypoint")
    entrypoint = entrypoints[0]
    app = entrypoint.parent.parent
    node = app / "node_modules/.bin/node-real"
    (destination / "prepared-manifest.json").write_text(json.dumps(snapshot(app), sort_keys=True, indent=2) + "\n")
    manifest["tools"]["cdxgen"] = {
        "binary": str(node),
        "sha256": digest(node),
        "entrypoint": str(entrypoint),
        "entrypoint_sha256": digest(entrypoint),
        "entrypoint_tree_sha256": tree_digest(app),
        "standalone_sha256": digest(standalone),
        "standalone_bytes": standalone.stat().st_size,
        "version_stdout": result.stdout.strip(),
        "version_stderr": result.stderr.strip(),
    }
    scalibr = pins["scalibr"]
    go_archive = destination / "go.tar.gz"
    download(
        f"https://go.dev/dl/go{scalibr['go_version']}.linux-{architecture}.tar.gz",
        go_archive,
        scalibr[f"go_{architecture}_archive_sha256"],
    )
    with tarfile.open(go_archive) as archive:
        archive.extractall(destination, filter="data")
    source = destination / "scalibr-source"
    subprocess.run(["git", "init", str(source)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(source), "remote", "add", "origin", "https://github.com/google/osv-scalibr.git"], check=True
    )
    subprocess.run(["git", "-C", str(source), "fetch", "--depth=1", "origin", scalibr["source_commit"]], check=True)
    subprocess.run(["git", "-C", str(source), "checkout", "--detach", "FETCH_HEAD"], check=True)
    actual = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if actual != scalibr["source_commit"]:
        raise ValueError("SCALIBR source commit mismatch")
    go = destination / "go/bin/go"
    env = {
        **os.environ,
        "GOTOOLCHAIN": "local",
        "GOCACHE": str(destination / "go-cache"),
        "GOPATH": str(destination / "go-modules"),
        "GOSUMDB": "sum.golang.org",
    }
    subprocess.run([str(go), "mod", "download"], cwd=source, env=env, check=True, timeout=1200)
    # Dependencies must already exist. Building never silently downloads a new
    # toolchain or resolves modules outside the commit's verified go.sum.
    subprocess.run([str(go), "mod", "verify"], cwd=source, env={**env, "GOPROXY": "off"}, check=True, timeout=120)
    scalibr_binary = destination / "scalibr"
    subprocess.run(
        [str(go), "build", *scalibr["build_flags"], "-o", str(scalibr_binary), "./binary/scalibr"],
        cwd=source,
        env={**env, "GOPROXY": "off"},
        check=True,
        timeout=1800,
    )
    manifest["tools"]["scalibr"] = {
        "binary": str(scalibr_binary),
        "sha256": digest(scalibr_binary),
        "binary_bytes": scalibr_binary.stat().st_size,
        "source_commit": actual,
        "go_archive_sha256": digest(go_archive),
        "go_mod_sha256": digest(source / "go.mod"),
        "go_sum_sha256": digest(source / "go.sum"),
        "build_flags": scalibr["build_flags"],
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.output)
