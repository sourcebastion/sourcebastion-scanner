"""Isolated finite-corpus projection/oracle audit, not resource acceptance."""

import argparse
import json
from pathlib import Path
import resource
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from evaluation.m046.corpus import CORPUS
from evaluation.m046.run import compare, MAX_OUTPUT
from evaluation.m046.static_native import supported, SUPPORTED_MANIFESTS
from evaluation.m046.syft_control_audit import decode
from evaluation.m046.syft_native import verify_projection


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--fixture", required=True)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (1024**3,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    if args.raw.stat().st_size > MAX_OUTPUT:
        raise ValueError("runtime finite-corpus raw limit exceeded")
    fixture = next(row for row in CORPUS if row["id"] == args.fixture)
    document = decode(args.raw.read_bytes())
    projection = verify_projection(document)
    comparison = compare(fixture["expected"], document["sidecar"]["inventory"])
    required = supported(fixture) or fixture["id"] in SUPPORTED_MANIFESTS
    if required and not comparison["full_contract_agreement"]:
        raise ValueError("runtime rich oracle disagreement")
    print(
        json.dumps(
            {
                "fixture": args.fixture,
                "projection": projection,
                "required_rich_contract": required,
                "full_contract_agreement": comparison["full_contract_agreement"],
                "inventory_status": document["sidecar"]["inventory"]["inventory_status"],
            }
        )
    )


if __name__ == "__main__":
    main()
