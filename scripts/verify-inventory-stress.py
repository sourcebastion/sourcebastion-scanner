"""Deterministic production-adapter stress with source-authored count oracles.

Large arms may explicitly refuse the frozen envelope; that is recorded as a
bounded capacity result, never a complete graph or a vulnerability-free scan.
The host driver owns actual resource measurement and one absolute watchdog.
"""

import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import time


def render(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def fixtures(arm):
    if arm.startswith("flat-"):
        count = int(arm.split("-")[1])
        return {"requirements.txt": "".join(f"p{number:06d}==1.0.0\n" for number in range(count)).encode()}, count, 0
    if arm == "graph":
        count = 40
        packages = {
            f"node_modules/p{number:03d}": {"version": "1.0.0", "dependencies": {
                f"p{child:03d}": "1.0.0" for child in range(count) if child != number
            }} for number in range(count)
        }
        return {"package-lock.json": render({"lockfileVersion": 3, "packages": packages})}, count, count * (count - 1)
    if arm == "expansion":
        # A diamond include DAG with 4096 possible paths but 26 unique files.
        # Includes do not encode package-to-package dependency edges.
        files = {"requirements.txt": b"-r level00a.txt\n-r level00b.txt\n"}
        for level in range(12):
            for side in "ab":
                files[f"level{level:02d}{side}.txt"] = (
                    f"-r level{level+1:02d}a.txt\n-r level{level+1:02d}b.txt\n".encode()
                    if level < 11 else f"leaf{side}==1.0.0\n".encode()
                )
        return files, 2, 0
    raise ValueError("unknown-stress-arm")


def run(arm):
    from sourcebastion.inventory.budget import PipelineBudget
    from sourcebastion.inventory.compose_source import compose_source
    from sourcebastion.inventory.contract import Producer, canonical_bytes
    from sourcebastion.inventory.cyclonedx import export
    from sourcebastion.inventory.inputs import Source, InputRefusal
    from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256

    started, files = time.monotonic(), fixtures(arm)
    inputs, expected_count, expected_edges = files
    config = DiscoveryConfig()
    identity = hashlib.sha256(render({name: hashlib.sha256(raw).hexdigest() for name, raw in inputs.items()})).hexdigest()
    producer = Producer(name="native-release-stress", version="1", code_sha256="a" * 64,
                        registry_sha256=REGISTRY_SHA256, config_sha256=config.sha256)
    report = {"schema_version": "m046.release-stress/1", "arm": arm, "source_sha256": identity,
              "expected_occurrences": expected_count, "expected_edges": expected_edges}
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        for name, raw in inputs.items():
            (root / name).write_bytes(raw)
        with Source(root) as source:
            budget = PipelineBudget(source, config=config, deadline=started + 150)
            value = compose_source(source, source_sha256=identity, producer=producer, config=config, budget=budget)
            report.update(inventory_state=value.stages.inventory, occurrences=len(value.occurrences),
                          edges=len(value.relationships), coverage=value.coverage.model_dump(mode="json"))
            if value.stages.inventory == "complete":
                if len(value.occurrences) != expected_count or len(value.relationships) != expected_edges:
                    raise ValueError("stress-independent-count-oracle-mismatch")
                if any(row.selected_version != "1.0.0" for row in value.occurrences):
                    raise ValueError("stress-independent-version-oracle-mismatch")
                if any(row.evidence_status != "evidenced" for row in value.relationships):
                    raise ValueError("stress-independent-edge-oracle-mismatch")
                report["inventory_sha256"] = hashlib.sha256(canonical_bytes(value)).hexdigest()
            elif not (
                any(row.disposition == "bounded-omission" for row in value.coverage.inputs)
                or (value.stages.inventory == "failed" and not value.occurrences and not value.relationships
                    and value.coverage.refusal_codes
                    and set(value.coverage.refusal_codes) <= {"composition-structure-budget-exceeded", "composition-record-budget-exceeded", "composition-semantic-budget-exceeded"})
            ):
                raise ValueError("stress-refusal-without-bounded-coverage")
            try:
                artifact = export(value, deadline=budget.deadline, check=budget.check)
                report["export"] = {"status": "succeeded", "bytes": len(artifact.content),
                                    "sha256": hashlib.sha256(artifact.content).hexdigest()}
            except (InputRefusal, ValueError) as error:
                report["export"] = {"status": "refused", "reason": type(error).__name__}
            if arm in {"flat-1000", "flat-10000", "graph", "expansion"}:
                if value.stages.inventory != "complete" or report["export"]["status"] != "succeeded":
                    raise ValueError("required-production-capacity-regression")
            source.validate()
            if any((root / name).read_bytes() != raw for name, raw in inputs.items()):
                raise ValueError("stress-source-mutated")
            report["semantic_checks"] = budget.consumed
    report["status"] = "passed"
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm", required=True, choices=("flat-1000", "flat-10000", "flat-100000", "flat-100001", "graph", "expansion"))
    run(parser.parse_args().arm)
