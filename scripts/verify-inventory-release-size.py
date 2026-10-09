"""Enforce frozen added compressed OCI layers against an immutable baseline."""

import argparse
import json
import tarfile
from pathlib import Path
from inventory_release import growth, oci_layers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--architecture", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--candidate-image", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    value = {"schema_version": "m046.compressed-release-growth/1", "status": "failed"}
    try:
        candidate = oci_layers(args.candidate, args.architecture)
        image = json.loads(args.candidate_image.read_text())
        if image["Id"] != candidate["config_digest"] or image["Architecture"] != args.architecture or image["Os"] != "linux":
            raise ValueError("compressed-candidate-is-not-tested-image")
        value.update(growth(oci_layers(args.baseline, args.architecture), candidate))
        value["tested_image_id"] = image["Id"]
        value["status"] = "passed"
    except (KeyError, ValueError, OSError, tarfile.TarError) as error:
        value["reason"] = str(error) if type(error) is ValueError else type(error).__name__
    with args.output.open("x") as stream:
        json.dump(value, stream, sort_keys=True)
    return 0 if value["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
