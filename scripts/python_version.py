"""Review an exact Python pin and refresh both architecture locks before release."""

import argparse
import importlib.util
import json
from pathlib import Path
import re
import tempfile
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
OFFICIAL_VERSIONS = "https://raw.githubusercontent.com/docker-library/python/master/versions.json"


def exact_version(value):
    if not isinstance(value, str) or not re.fullmatch(r"3\.[0-9]+\.[0-9]+", value):
        raise ValueError("Python version must be an exact stable 3.MINOR.PATCH value")
    return value


def current(requested=""):
    version = exact_version((ROOT / "PYTHON_VERSION").read_text().strip())
    dockerfile = (ROOT / "images/Dockerfile").read_text()
    if not re.search(r"^ARG PYTHON_VERSION=" + re.escape(version) + r"$", dockerfile, re.MULTILINE):
        raise ValueError("Dockerfile default and PYTHON_VERSION disagree")
    if requested and exact_version(requested) != version:
        raise ValueError("requested Python version must match the reviewed source pin")
    return version


def stable_candidates(metadata):
    versions = {item.get("version") for item in metadata.values()
                if "alpine3.23" in item.get("variants", [])
                and re.fullmatch(r"3\.[0-9]+\.[0-9]+", item.get("version", ""))}
    return sorted(versions, key=lambda version: tuple(map(int, version.split("."))), reverse=True)


def artifact_tools():
    spec = importlib.util.spec_from_file_location("release_artifacts", ROOT / "scripts/scanner_artifacts.py")
    artifacts = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(artifacts)
    return artifacts


def update(requested):
    with urlopen(OFFICIAL_VERSIONS, timeout=60) as response:
        candidates = stable_candidates(json.load(response))
    previous = tuple(map(int, current().split(".")))
    if requested != "latest":
        candidates = [exact_version(requested)]
    else:
        candidates = [v for v in candidates if tuple(map(int, v.split("."))) >= previous]
    if not candidates:
        raise ValueError("no stable Python candidate is available without downgrading")
    artifacts = artifact_tools()
    lock = artifacts.validate_lock(json.loads((ROOT / ".github/semgrep-artifacts.json").read_text()))
    artifacts.verify(lock)
    failures = []
    for version in candidates:
        artifacts.configure_python(version)
        with tempfile.TemporaryDirectory(prefix="sourcebastion-python-") as temporary:
            staged = Path(temporary)
            try:
                artifacts.generate_dependencies(lock, staged)
            except ValueError as exc:
                if requested != "latest":
                    raise
                failures.append(f"{version}: {exc}")
                continue
            # Only update reviewed files after all wheels and target closures verify.
            destination = ROOT / ".github/python-locks"
            for path in destination.glob("*.txt"):
                path.unlink()
            for path in staged.iterdir():
                (destination / path.name).write_bytes(path.read_bytes())
            (ROOT / "PYTHON_VERSION").write_text(version + "\n")
            dockerfile = ROOT / "images/Dockerfile"
            dockerfile.write_text(re.sub(r"^ARG PYTHON_VERSION=.*$", "ARG PYTHON_VERSION=" + version,
                                        dockerfile.read_text(), flags=re.MULTILINE))
            return version
    raise ValueError("no compatible stable Python candidate: " + "; ".join(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("current", "update"))
    parser.add_argument("--requested", default="")
    parser.add_argument("--version", default="latest")
    args = parser.parse_args()
    try:
        print(current(args.requested) if args.command == "current" else update(args.version))
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, f"Python version validation failed: {exc}\n")


if __name__ == "__main__":
    main()
