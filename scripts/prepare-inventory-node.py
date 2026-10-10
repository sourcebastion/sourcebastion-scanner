"""Trusted image build only: verify native Node/npm APKs before installation."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
from urllib.request import urlopen


def prepare(pins, output):
    value = json.loads(pins.read_text())
    architecture = platform.machine()
    if value["schema_version"] != "sourcebastion.inventory-runtime-pins/1" or architecture not in {"x86_64", "aarch64"}:
        raise ValueError("native-inventory-runtime-pin-required")
    output.mkdir(parents=True, exist_ok=False)
    for name in ("nodejs", "npm"):
        row = value["packages"][name]
        filename = name + "-" + row["version"] + ".apk"
        url = f"https://dl-cdn.alpinelinux.org/alpine/v{value['alpine']}/{row['repository']}/{architecture}/{filename}"
        digest, count = hashlib.sha256(), 0
        with urlopen(url, timeout=60) as response, (output / filename).open("xb") as stream:
            while chunk := response.read(1024**2):
                count += len(chunk)
                if count > 64 * 1024**2:
                    raise ValueError("inventory-runtime-download-bound")
                digest.update(chunk)
                stream.write(chunk)
        if digest.hexdigest() != row["sha256"][architecture]:
            raise ValueError("inventory-runtime-package-digest-mismatch")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pins", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    prepare(args.pins, args.output)
