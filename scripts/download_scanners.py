"""Download only the pinned scanner binary for the native architecture."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import tarfile
import tempfile
from urllib.request import urlopen

ARCHES = {"x86_64": ("x64", "amd64", "x86"), "aarch64": ("arm64", "arm64", "aarch64")}
TOOLS = {"gitleaks": ("gitleaks", 0), "grype": ("anchore", 1), "opengrep": ("opengrep", 2)}


def download_tool(tool, pins, machine, destination):
    owner, index = TOOLS[tool]
    arch = ARCHES[machine][index]
    version = pins[tool]["version"]
    digest = pins[tool]["linux_" + arch + "_sha256"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("scanner requires an exact version and SHA-256")
    filename = f"{tool}_{version}_linux_{arch}.tar.gz"
    if tool == "opengrep":
        filename = f"opengrep_linux_{arch}"
    url = f"https://github.com/{owner}/{tool}/releases/download/v{version}/{filename}"
    with urlopen(url, timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"{tool}: artifact SHA-256 mismatch")
    if tool == "opengrep":
        binary = destination / tool
        binary.write_bytes(data)
        binary.chmod(0o755)
        return
    with tempfile.TemporaryDirectory() as temporary:
        archive = Path(temporary) / filename
        archive.write_bytes(data)
        with tarfile.open(archive) as handle:
            member = handle.getmember(tool)
            if not member.isfile():
                raise ValueError("scanner archive must contain a regular binary")
            handle.extract(member, destination, filter="data")
    (destination / tool).chmod(0o755)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pins", required=True, type=Path)
    parser.add_argument("--destination", default=Path("/usr/local/bin"), type=Path)
    parser.add_argument("--tool", choices=TOOLS)
    args = parser.parse_args()
    pins = json.loads(args.pins.read_text())
    args.destination.mkdir(parents=True, exist_ok=True)
    for tool in (args.tool,) if args.tool else TOOLS:
        download_tool(tool, pins, platform.machine(), args.destination)
