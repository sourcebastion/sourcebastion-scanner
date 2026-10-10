"""Enforce frozen added compressed OCI layers against an immutable baseline."""

import argparse
import json
import tarfile
from pathlib import Path
from inventory_release import frozen_s01_layers, growth, oci_layers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--architecture", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--candidate-image", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--frozen-s01", action="store_true",
                        help="Require the retained S01 OCI archive and charge every layer added beyond its pre-inventory prefix")
    args = parser.parse_args()
    value = {"schema_version": "m046.compressed-release-growth/1", "status": "failed"}
    try:
        candidate = oci_layers(args.candidate, args.architecture)
        image = json.loads(args.candidate_image.read_text())
        if image["Id"] != candidate["config_digest"] or image["Architecture"] != args.architecture or image["Os"] != "linux":
            raise ValueError("compressed-candidate-is-not-tested-image")
        baseline = frozen_s01_layers(args.baseline, args.architecture) if args.frozen_s01 else oci_layers(args.baseline, args.architecture)
        value.update(growth(baseline, candidate))
        if args.frozen_s01:
            value.update({key: val for key, val in baseline.items() if key.startswith("baseline_")})
        value["tested_image_id"] = image["Id"]
        value["status"] = "passed"
    except (KeyError, ValueError, OSError, tarfile.TarError) as error:
        value["reason"] = str(error) if type(error) is ValueError else type(error).__name__
    with args.output.open("x") as stream:
        json.dump(value, stream, sort_keys=True)
    return 0 if value["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
