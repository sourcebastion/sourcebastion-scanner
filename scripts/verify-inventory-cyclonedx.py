"""Actual installed generated-only CycloneDX artifacts for offline validation."""

import hashlib
import json
from pathlib import Path
import platform
import sys
import tempfile
import time


def require_unoptimized():
    if sys.flags.optimize:
        raise RuntimeError("optimized-probe-runtime-refused")


def verify():
    require_unoptimized()
    from sourcebastion.inventory.compose_source import compose_source
    from sourcebastion.inventory.contract import Producer, canonical_bytes
    from sourcebastion.inventory.cyclonedx import export, VERSION, SCHEMAS
    from sourcebastion.inventory.inputs import Source
    from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256

    fixtures = [
        ("custom-input", {"build/production.pin": b"pip==26.0.1\n"}, (("build/production.pin", "pip-requirements"),)),
        ("hidden-input", {".hidden/locked.txt": b"pip==26.0.1\n"}, ()),
        (
            "two-analysis-contexts",
            {"one/requirements.txt": b"pip==26.0.1\n", "two/requirements.txt": b"pip==26.0.1\n"},
            (),
        ),
        ("range-only", {"requirements.txt": b"pip>=20\n"}, ()),
        ("unknown-activation", {"requirements.txt": b'pip==26.0.1; python_version < "4"\n'}, ()),
        ("patched-pin", {"requirements.txt": b"pip==26.2\n"}, ()),
        (
            "mixed-ecosystems",
            {"requirements.txt": b"pip==26.0.1\n", "package.json": b'{"dependencies":{"@scope/package":"1.2.3"}}'},
            (),
        ),
        (
            "unsupported-remains-visible",
            {
                "requirements.txt": b"pip==26.0.1\n",
                "go.mod": b"module example.invalid/root\nrequire example.invalid/package v1.2.3\n",
            },
            (),
        ),
    ]
    records = []
    for name, files, mappings in fixtures:
        config = DiscoveryConfig(mappings=mappings)
        source_identity = hashlib.sha256(
            json.dumps(
                {key: hashlib.sha256(value).hexdigest() for key, value in sorted(files.items())}, sort_keys=True
            ).encode()
        ).hexdigest()
        producer = Producer(
            name="native-fixed-controller",
            version="1",
            code_sha256="a" * 64,
            registry_sha256=REGISTRY_SHA256,
            config_sha256=config.sha256,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path, content in files.items():
                item = root / path
                item.parent.mkdir(parents=True, exist_ok=True)
                item.write_bytes(content)
            with Source(root) as source:
                original = compose_source(source, source_sha256=source_identity, producer=producer, config=config)
                before = canonical_bytes(original)
                artifact = export(original, deadline=source.deadline, check=source.check)
                repeated = export(original, deadline=source.deadline, check=source.check)
                assert artifact == repeated and canonical_bytes(original) == before
                source.validate()
        document = json.loads(artifact.content)
        assert artifact.scope_losses == len(document["components"])
        assert hashlib.sha256(artifact.content).hexdigest() == artifact.sha256
        assert hashlib.sha256(before).hexdigest() == artifact.inventory_sha256
        assert original.stages.export == original.stages.matching == "not-run"
        if name == "range-only":
            assert not document["components"] and artifact.omitted_occurrences == 1
        if name == "two-analysis-contexts":
            assert len(document["components"]) == 2 and len({row["bom-ref"] for row in document["components"]}) == 2
        if name == "unsupported-remains-visible":
            assert original.stages.inventory == "partial" and len(document["components"]) == 1
        records.append(
            {
                "case": name,
                "inventory": json.loads(before),
                "document": document,
                "inventory_sha256": artifact.inventory_sha256,
                "bom_sha256": artifact.sha256,
                "identity_sha256": artifact.identity_sha256,
                "omitted_occurrences": artifact.omitted_occurrences,
                "omitted_relationships": artifact.omitted_relationships,
                "scope_losses": artifact.scope_losses,
            }
        )
    modules = {}
    checkout = Path.cwd().resolve()
    for name, module in sorted(sys.modules.items()):
        if not name.startswith("sourcebastion.inventory") or not getattr(module, "__file__", None):
            continue
        path = Path(module.__file__).resolve()
        assert not path.is_relative_to(checkout)
        relative = Path(*name.split("."))
        expected = relative / "__init__.py" if path.name == "__init__.py" else relative.with_suffix(".py")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        assert actual == hashlib.sha256((checkout / expected).read_bytes()).hexdigest()
        modules[str(expected)] = actual
    rendered = json.dumps(
        {
            "schema_version": "sourcebastion.cyclonedx-native-proof/1",
            "status": "native-installed-cyclonedx-generated",
            "python": platform.python_version(),
            "architecture": platform.machine(),
            "exporter": VERSION,
            "schemas": SCHEMAS,
            "source_modules": modules,
            "cases": records,
            "scope": "eight finite installed exports; official validation is a separate host gate; no real Grype, rich or whole-pipeline acceptance",
        },
        sort_keys=True,
    )
    assert len(rendered.encode()) <= 64 * 1024 * 1024
    print(rendered)


if __name__ == "__main__":
    try:
        verify()
    except Exception as error:
        print(json.dumps({"status": "native-installed-cyclonedx-failed", "reason": type(error).__name__}))
        raise
