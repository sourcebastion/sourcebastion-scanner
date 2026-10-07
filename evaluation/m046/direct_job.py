"""Trusted direct Python candidate; synthetic resource experiment only.

The unchanged outer controller owns namespaces, cgroups, deadlines and capture.
No installer, subprocess or scanned source module is invoked here.
"""

import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from evaluation.m046.static_cli import encode, failed
from evaluation.m046.static_inputs import InputRefusal, Source
from evaluation.m046.static_inventory import evaluate


def candidate(mode, root, provenance):
    if mode not in {"direct-inventory", "direct-cyclonedx"}:
        raise ValueError("explicit direct candidate mode required")
    inventory = None
    stage = "inventory-evaluation"
    try:
        with Source(root) as source:
            inventory = evaluate(source)
            if inventory["inventory_status"] == "failed":
                raise InputRefusal(inventory["refusal_codes"][0])
            # Measure the same bounded inventory serialization in both arms.
            stage = "inventory-serialization"
            inventory_bytes = encode(inventory, deadline=source.deadline)
            if mode == "direct-inventory":
                content = inventory_bytes
            else:
                from evaluation.m046.cyclonedx_export import export

                stage = "export"
                content = export(inventory, provenance=provenance, deadline=source.deadline)
            source.check()
            return content, 0
    except InputRefusal as refusal:
        if stage != "export":
            document = failed(refusal.reason)
            document["refusal_stage"] = stage
            document["source_inventory_status"] = inventory["inventory_status"] if inventory is not None else "unknown"
        else:
            document = {
                "status": "evaluation-export-refused",
                "inventory_status": inventory["inventory_status"],
                "sbom_status": "failed",
                "matching_status": "not-run",
                "reason": refusal.reason,
                "inventory_retention": "not-assessed; this job retains one measured output only",
            }
        return encode(document), 2


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {"direct-inventory", "direct-cyclonedx"}:
        raise ValueError("one explicit direct candidate mode required")
    root = Path(__file__).resolve().parent
    provenance = json.loads((root / "provenance.json").read_text())
    packages = {}
    for name in (
        "packaging",
        "poetry-core",
        "jsonschema",
        "referencing",
        "attrs",
        "rpds-py",
        "jsonschema-specifications",
    ):
        distribution = importlib.metadata.distribution(name)
        packages[name] = {
            "version": distribution.version,
            "sources": {
                str(path): hashlib.sha256(distribution.locate_file(path).read_bytes()).hexdigest()
                for path in distribution.files or ()
                if path.suffix in {".py", ".so"}
            },
        }
    print(
        json.dumps({"python": platform.python_version(), "architecture": platform.machine(), "packages": packages}),
        flush=True,
    )
    content, status = candidate(sys.argv[1], Path("/source"), provenance)
    descriptor = os.open("/work/raw.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), 0o644)
        stream.write(content)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
