#!/usr/bin/env python3
"""Exercise installed S02 code on each native release image, entirely offline."""

import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import sys
import tempfile

import packaging
from sourcebastion.inventory import discover
from sourcebastion.inventory import discovery, inputs, registry, requirements
from sourcebastion.inventory.inputs import Limits, Source
from sourcebastion.inventory.registry import DiscoveryConfig, format_for


def write(root, path, data):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data.encode())


def check(root, config=None, limits=None):
    with Source(root, limits) as source:
        result = discover(source, config=config)
    return result, {r.path: r for r in result.inputs}


def main():
    if sys.flags.optimize:
        raise RuntimeError("optimized-probe-runtime-refused")
    signal.alarm(60)
    assert packaging.__version__ == "26.3"
    modules = [discovery, inputs, registry, requirements]
    # A mounted checkout must never shadow the built wheel under test.
    for module in modules:
        assert "/site-packages/sourcebastion/inventory/" in module.__file__, module.__file__
    corpus = json.loads(Path("tests/fixtures/inventory/corpus.json").read_text())
    assert len(corpus) == 64
    proofs = []
    for fixture in corpus:
        with tempfile.TemporaryDirectory(prefix="inventory-native-") as temporary:
            root = Path(temporary)
            for path, content in fixture["files"].items():
                write(root, path, content)
            for path, target in fixture["symlinks"].items():
                link = root / path
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(target)
            before = {path: (root / path).read_bytes() for path in fixture["files"]}
            first, rows = check(root)
            assert first == check(root)[0]
            assert before == {path: (root / path).read_bytes() for path in fixture["files"]}
            for path in fixture["files"]:
                if format_for(path, DiscoveryConfig()):
                    assert path in rows
            for path in fixture["symlinks"]:
                assert rows[path].reason == "unsupported-symlink"
            proofs.append(
                {
                    "fixture": fixture["id"],
                    "status": first.status,
                    "discovery_sha256": hashlib.sha256(
                        json.dumps(first.to_dict(), sort_keys=True).encode()
                    ).hexdigest(),
                }
            )
    with tempfile.TemporaryDirectory(prefix="inventory-native-contract-") as temporary:
        root = Path(temporary)
        write(root, "requirements.txt", "-r .hidden/base.config\n-c constraints.txt\n")
        write(root, ".hidden/base.config", "requests\n")
        write(root, "constraints.txt", "requests==2.32.3\n")
        first, rows = check(root)
        assert first.status == "complete" and rows[".hidden/base.config"].disposition == "parsed"
        assert ("requirements.txt", "constraints.txt", "constraint") in first.contexts
        assert ("requirements.txt", ".hidden/base.config", "requirement") in first.contexts
        for url in ["https://user:private@example.invalid/data", "//user:private@example.invalid/data"]:
            write(root, "requirements.txt", "-r " + url + "\n")
            result, rows = check(root)
            assert result.status == "partial" and "private" not in json.dumps(result.to_dict())
        os.mkfifo(root / "queue.pip")
        result, rows = check(root)
        assert rows["queue.pip"].reason == "unsupported-special"
        result, rows = check(root, limits=Limits(entries=1))
        assert "input-traversal-budget-exceeded" in result.refusal_codes
    with tempfile.TemporaryDirectory(prefix="inventory-native-epoch-") as temporary:
        root = Path(temporary)
        write(root, "a.txt", "pip==26.0.1\n")
        write(root, "b.txt", "pip==26.0.1\n")
        target = root / "b.txt"
        real_read = os.read
        mutated = False

        def mutate(descriptor, count):
            nonlocal mutated
            chunk = real_read(descriptor, count)
            if chunk and not mutated and os.fstat(descriptor).st_ino == target.stat().st_ino:
                write(root, "b.txt", "pip==26.2\n")
                mutated = True
            return chunk

        try:
            os.read = mutate
            result, rows = check(root)
            assert mutated and result.status == "failed" and not result.documents
            assert "changed-input-bytes" in result.refusal_codes
        finally:
            os.read = real_read
    print(
        json.dumps(
            {
                "status": "native-installed-discovery-contracts-passed",
                "python": platform.python_version(),
                "architecture": platform.machine(),
                "packaging": packaging.__version__,
                "source_modules": {
                    Path(m.__file__).name: hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest() for m in modules
                },
                "fixtures": proofs,
                "scope": "discovery/immutability/constraint/escape/FIFO/budget probes; not canonical graph or full pipeline acceptance",
            },
            sort_keys=True,
            indent=2,
        )
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Preserve a bounded failed checkpoint without source text/credentials.
        # Failure exit and missing/incomplete records never qualify acceptance.
        print(json.dumps({"status": "native-discovery-failed", "reason": type(error).__name__}, sort_keys=True))
        raise
