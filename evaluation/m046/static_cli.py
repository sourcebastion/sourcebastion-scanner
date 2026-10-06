"""Bounded stdout entrypoint for controlled synthetic adapter experiments."""

import argparse
import io
import json
from pathlib import Path
import sys
import time

if not __package__:
    # This file and its ancestor tree are trusted controller-prepared code.
    # Never add the scanned root or process working directory to import paths.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from evaluation.m046.static_inputs import InputRefusal, Source
from evaluation.m046.static_inventory import VERSION, evaluate

MAX_OUTPUT = 64 * 1024 * 1024


def encode(document, *, limit=MAX_OUTPUT, deadline=None):
    """Prepare the entire bounded result before emitting any stdout bytes."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_OUTPUT:
        raise ValueError("invalid-output-limit")
    stream = io.BytesIO()
    if deadline is None:
        deadline = time.monotonic() + 150
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    for piece in encoder.iterencode(document):
        if time.monotonic() > deadline:
            raise InputRefusal("input-deadline-exceeded")
        block = piece.encode("ascii")
        if stream.tell() + len(block) + 1 > limit:
            raise InputRefusal("inventory-output-budget-exceeded")
        stream.write(block)
    stream.write(b"\n")
    return stream.getvalue()


def failed(reason):
    return {
        "schema_version": VERSION,
        "inventory_status": "failed",
        "sbom_status": "not-run",
        "matching_status": "not-run",
        "packages": [],
        "edges": [],
        "application_identities": [],
        "coverage": "prototype-static-python",
        "refusal_codes": [reason],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        with Source(args.root) as source:
            document = evaluate(source)
            content = encode(document, deadline=source.deadline)
            source.check()
    except InputRefusal as refusal:
        document = failed(refusal.reason)
        content = encode(document)
    sys.stdout.buffer.write(content)
    return 2 if document["inventory_status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
