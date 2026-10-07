"""Finite installed recovery guards with synthetic reports, not real SCA."""

import hashlib
import json
from pathlib import Path
import platform
import sys
import tempfile
import time
from dataclasses import replace


def verify():
    if sys.flags.optimize:
        raise RuntimeError("optimized-probe-runtime-refused")
    from sourcebastion.inventory.compose_source import compose_source
    from sourcebastion.inventory.contract import Producer, canonical_bytes
    from sourcebastion.inventory.cyclonedx import export
    from sourcebastion.inventory.inputs import Source
    from sourcebastion.inventory.matching import Consumer, recover
    from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256

    config = DiscoveryConfig()
    producer = Producer(
        name="native-fixed-controller",
        version="1",
        code_sha256="a" * 64,
        registry_sha256=REGISTRY_SHA256,
        config_sha256=config.sha256,
    )
    consumer = Consumer(
        binary_sha256="b" * 64,
        version="0.119.0",
        config_sha256="c" * 64,
        advisory_snapshot_sha256="d" * 64,
        advisory_schema="v6.1.10",
        advisory_built="2026-10-06T06:32:14Z",
    )
    cases = []
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for relative in ("one/requirements.txt", "two/requirements.txt"):
            target = root / relative
            target.parent.mkdir()
            target.write_text('pip==26.0.1; python_version < "4"\n')
        with Source(root) as source:
            value = compose_source(source, source_sha256="a" * 64, producer=producer, config=config)
            before = canonical_bytes(value)
            artifact = export(value, deadline=source.deadline, check=source.check)
            report = {
                "source": {"type": "sbom-file"},
                "descriptor": {
                    "name": "grype",
                    "version": consumer.version,
                    "db": {
                        "status": {
                            "valid": True,
                            "schemaVersion": consumer.advisory_schema,
                            "built": consumer.advisory_built,
                        }
                    },
                },
                "matches": [
                    {
                        "artifact": {
                            "id": row.id,
                            "type": "python",
                            "name": row.name,
                            "version": row.selected_version,
                            "purl": row.purl,
                            "locations": None,
                        },
                        "vulnerability": {
                            "id": "TEST-SYNTHETIC",
                            "namespace": "synthetic-test",
                            "severity": "Medium",
                            "fix": {"versions": ["26.2"]},
                        },
                    }
                    for row in value.occurrences
                ],
            }

            def run(payload, candidate=artifact):
                return recover(
                    value,
                    candidate,
                    json.dumps(payload, sort_keys=True).encode(),
                    consumer=consumer,
                    deadline=source.deadline,
                    check=source.check,
                )

            result = run(report)
            assert len(result.matches) == len(result.occurrence_contexts) == 2
            assert len({row.occurrence_id for row in result.matches}) == 2
            assert all(json.loads(raw)["activation"] == "unknown" for _, raw in result.occurrence_contexts)
            assert run(report) == result
            cases.append(
                {
                    "case": "two-contexts-synthetic-original-findings",
                    "recovery_identity": result.identity_sha256,
                    "matches": 2,
                }
            )
            for field, wrong in (
                ("id", "unknown"),
                ("type", "npm"),
                ("version", "26.2"),
                ("name", "other"),
                ("purl", "pkg:pypi/other@26.0.1"),
            ):
                altered = json.loads(json.dumps(report))
                altered["matches"][0]["artifact"][field] = wrong
                try:
                    run(altered)
                except ValueError:
                    pass
                else:
                    raise AssertionError("contradictory-occurrence-accepted")
                cases.append({"case": "reject-artifact-" + field})
            try:
                run(report, replace(artifact, identity_sha256="0" * 64))
            except ValueError:
                pass
            else:
                raise AssertionError("forged-export-accepted")
            cases.append({"case": "reject-forged-export"})
            empty = json.loads(json.dumps(report))
            empty["matches"] = []
            assert not run(empty).matches
            cases.append({"case": "valid-zero-synthetic-report"})
            malformed = json.loads(json.dumps(report))
            malformed["descriptor"]["db"]["status"]["valid"] = False
            try:
                run(malformed)
            except ValueError:
                pass
            else:
                raise AssertionError("invalid-database-accepted")
            cases.append({"case": "reject-invalid-advisory"})
            assert canonical_bytes(value) == before and value.stages.matching == value.stages.export == "not-run"
            source.validate()
    modules = {}
    checkout = Path.cwd().resolve()
    for name, module in sorted(sys.modules.items()):
        if not name.startswith("sourcebastion.inventory") or not getattr(module, "__file__", None):
            continue
        path = Path(module.__file__).resolve()
        assert not path.is_relative_to(checkout)
        relative = Path(*name.split("."))
        relative = relative / "__init__.py" if path.name == "__init__.py" else relative.with_suffix(".py")
        checksum = hashlib.sha256(path.read_bytes()).hexdigest()
        assert checksum == hashlib.sha256((checkout / relative).read_bytes()).hexdigest()
        modules[str(relative)] = checksum
    print(
        json.dumps(
            {
                "schema_version": "sourcebastion.match-recovery-native-proof/1",
                "status": "native-installed-match-recovery-finite",
                "python": platform.python_version(),
                "architecture": platform.machine(),
                "cases": cases,
                "source_modules": modules,
                "scope": "Nine finite guards using synthetic reports; no actual native Grype execution, advisory authenticity, isolation or S04 acceptance.",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    try:
        verify()
    except Exception as error:
        print(json.dumps({"status": "native-installed-match-recovery-failed", "reason": type(error).__name__}))
        raise
