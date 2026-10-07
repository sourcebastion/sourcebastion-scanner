"""Bounded controller-side comparison of restricted provider raw evidence."""

import argparse
import hashlib
import json
from pathlib import Path
import resource
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from evaluation.m046.provider_corpus import PROVIDER_CORPUS
from evaluation.m046.provider_evidence import bind_sources, comparison, facts
from evaluation.m046.static_cli import encode
from evaluation.m046.syft_control_audit import decode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--facts-output", type=Path, required=True)
    parser.add_argument("--source-snapshot", type=Path)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (1024**3,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    if args.raw.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("provider-raw-budget-exceeded")
    document = decode(args.raw.read_bytes())
    fixture = next(row for row in PROVIDER_CORPUS if row["id"] == args.fixture)
    extracted = facts(document)
    result = {"facts": extracted, "comparison": comparison(fixture["expected"], document)}
    if args.source_snapshot is not None:
        if args.source_snapshot.stat().st_size > 64 * 1024 * 1024:
            raise ValueError("provider-snapshot-budget-exceeded")
        result["source_binding"] = bind_sources(extracted, decode(args.source_snapshot.read_bytes()))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024,) * 2)
    content = encode(result)
    with args.facts_output.open("xb") as stream:
        stream.write(content)
    sys.stdout.buffer.write(
        encode({"facts_sha256": hashlib.sha256(content).hexdigest(), "comparison": result["comparison"]})
    )


if __name__ == "__main__":
    main()
