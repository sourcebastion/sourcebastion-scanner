"""Trusted in-image identity probe; no project inputs or installations."""

import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import signal
import sys


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def guard(seconds=20):
    signal.signal(signal.SIGALRM, lambda *_args: os._exit(124))
    signal.alarm(seconds)


def main():
    root = Path("/opt/m046")
    packages = {}
    for distribution, prefix in (("packaging", "packaging"), ("poetry-core", "poetry")):
        installed = importlib.metadata.distribution(distribution)
        packages[distribution] = {
            "version": installed.version,
            "sources": {
                str(path): sha(installed.locate_file(path))
                for path in installed.files or ()
                if path.suffix == ".py" and path.parts[0] == prefix
            },
        }
    print(
        json.dumps(
            {
                "python": platform.python_version(),
                "architecture": platform.machine(),
                "executable": sys.executable,
                "prefix": sys.prefix,
                "isolated": sys.flags.isolated,
                "binary_sha256": sha(root / "bin/m046-syft"),
                "frontend": {
                    str(path.relative_to(root / "frontend")): sha(path)
                    for path in sorted((root / "frontend").rglob("*.py"))
                },
                "packages": packages,
            }
        )
    )


if __name__ == "__main__":
    guard()
    main()
