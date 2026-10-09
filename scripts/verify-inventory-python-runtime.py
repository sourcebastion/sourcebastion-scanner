#!/usr/bin/env python3
"""Finite supported-Python import/composition proof; no installed/native custody."""

import hashlib
import json
import platform
from pathlib import Path
import sys
import tempfile

from sourcebastion.inventory.compose_source import compose_source
from sourcebastion.inventory.contract import Producer, canonical_bytes
from sourcebastion.inventory.inputs import Source
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256


def main():
    if sys.flags.optimize or sys.version_info < (3, 9):
        raise RuntimeError("supported-unoptimized-python-required")
    path = Path(__file__).resolve().parents[1] / "evaluation/m046/canonical-source-expectations-v1.json"
    raw = path.read_bytes()
    document = json.loads(raw)
    selected = {"ruby-lock", "php-lock", "dotnet-lock", "python-requirements"}
    cases = [case for case in document["cases"] if case["case"] in selected]
    assert len(cases) == len(selected)
    config = DiscoveryConfig()
    producer = Producer(
        name="python-runtime-compatibility",
        version="1",
        code_sha256="a" * 64,
        registry_sha256=REGISTRY_SHA256,
        config_sha256=config.sha256,
    )
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        files = {}
        for case in cases:
            for row in case["fixture_files"]:
                assert row["path"] not in files and "/" not in row["path"]
                content = row["utf8"].encode()
                assert hashlib.sha256(content).hexdigest() == row["sha256"]
                files[row["path"]] = content
                (root / row["path"]).write_bytes(content)
        source_sha256 = hashlib.sha256(
            json.dumps(
                {name: hashlib.sha256(content).hexdigest() for name, content in files.items()}, sort_keys=True
            ).encode()
        ).hexdigest()

        def run():
            with Source(root) as source:
                result = compose_source(source, source_sha256=source_sha256, producer=producer, config=config)
                source.validate()
                return result

        result = run()
        observed = {(row.ecosystem, row.name, row.selected_version) for row in result.occurrences}
        assert {
            ("gem", "rack", "3.1.7"),
            ("composer", "psr/log", "3.0.2"),
            ("nuget", "newtonsoft.json", "13.0.3"),
            ("pypi", "requests", "2.32.3"),
        } == observed
        assert result.stages.inventory == "partial" and not result.relationships
        encoded = canonical_bytes(result)
        assert canonical_bytes(run()) == encoded
        assert all((root / name).read_bytes() == content for name, content in files.items())
    assert path.read_bytes() == raw
    print(
        json.dumps(
            {
                "python": platform.python_version(),
                "status": "passed",
                "occurrences": len(observed),
                "repeatable": True,
                "inventory_sha256": hashlib.sha256(encoded).hexdigest(),
                "scope": "Finite checkout-source compatibility proof; no installed/native/runtime-custody acceptance.",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
