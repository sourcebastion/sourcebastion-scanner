"""Trusted source-free Alpine import/one-export feasibility probe, not a scan route."""

import hashlib
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import signal
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from direct_job import candidate
else:
    from evaluation.m046.direct_job import candidate

PACKAGES = ("packaging", "poetry-core", "jsonschema", "referencing", "attrs", "rpds-py", "jsonschema-specifications")


def code_member(path):
    return path.suffix in {".py", ".so"} or ".so." in path.name


def sha(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 32 * 1024**2:
        raise ValueError("bounded regular runtime closure file required")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def loaded_closure(maps):
    if len(maps) > 1024**2:
        raise ValueError("loaded map budget exceeded")
    paths = set()
    for row in maps.splitlines():
        fields = row.split(maxsplit=5)
        if len(fields) != 6 or not fields[5].startswith("/"):
            continue
        path = Path(fields[5])
        if ".so" in path.name:
            if " (deleted)" in str(path) or len(paths) >= 256:
                raise ValueError("uncertain loaded library identity")
            paths.add(path)
    if not paths:
        raise ValueError("loaded native closure unavailable")
    return {str(path): sha(path.resolve(strict=True)) for path in sorted(paths)}


def main():
    signal.signal(signal.SIGALRM, lambda *_: os._exit(124))
    signal.alarm(25)
    root = Path(__file__).resolve().parent
    for name in ("packaging", "poetry.core", "jsonschema", "referencing", "attrs", "rpds", "jsonschema_specifications"):
        importlib.import_module(name)
    from rpds import HashTrieMap

    if HashTrieMap({"probe": 1})["probe"] != 1:
        raise ValueError("native map operation failed")
    packages = {}
    for name in PACKAGES:
        distribution = importlib.metadata.distribution(name)
        packages[name] = {
            "version": distribution.version,
            "sources": {
                str(path): sha(distribution.locate_file(path)) for path in distribution.files or () if code_member(path)
            },
        }
    content, status = candidate("direct-cyclonedx", Path("/source"), json.loads((root / "provenance.json").read_text()))
    if status:
        raise ValueError("finite Alpine export refused")
    report = {
        "status": "finite-import-export-only",
        "python": platform.python_version(),
        "architecture": platform.machine(),
        "executable": sys.executable,
        "prefix": sys.prefix,
        "isolated": sys.flags.isolated,
        "uid": os.getuid(),
        "gid": os.getgid(),
        "os_release": Path("/etc/os-release").read_text(),
        "packages": packages,
        "frontend": {str(path.relative_to(root)): sha(path) for path in sorted(root.rglob("*")) if path.is_file()},
        "loaded_libraries": loaded_closure(Path("/proc/self/maps").read_text()),
        "sbom": json.loads(content),
        "full_contract_qualified": False,
    }
    sys.stdout.write(json.dumps(report, sort_keys=True, allow_nan=False) + "\n")


if __name__ == "__main__":
    main()
