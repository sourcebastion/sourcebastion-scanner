"""Trusted image build: retain and verify exact Node/npm APKs before installation."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import time
from urllib.error import HTTPError, URLError
from urllib.request import urlopen


ARCHITECTURES = {"x86_64", "aarch64"}
RELEASES = "https://github.com/sourcebastion/sourcebastion-scanner/releases/download"


def package_version(row, architecture):
    return row.get("versions", {}).get(architecture, row["version"])


def release_tag(value):
    identity = {key: value[key] for key in ("alpine", "node_version", "packages")}
    raw = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    return "runtime-apks-" + hashlib.sha256(raw).hexdigest()


def validate(value, architecture):
    if (value["schema_version"] != "sourcebastion.inventory-runtime-pins/1"
            or architecture not in ARCHITECTURES or set(value["packages"]) != {"nodejs", "npm"}
            or not re.fullmatch(r"[0-9]+\.[0-9]+", value["alpine"])):
        raise ValueError("native-inventory-runtime-pin-required")
    for row in value["packages"].values():
        if (row["repository"] not in {"main", "community"}
                or set(row["sha256"]) != ARCHITECTURES
                or set(row.get("versions", {})) - ARCHITECTURES
                or not re.fullmatch(r"[0-9][0-9a-z._+-]*", package_version(row, architecture))
                or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"][architecture])):
            raise ValueError("invalid-inventory-runtime-pin")


def download(url, destination, expected):
    for attempt in range(3):
        try:
            digest, count = hashlib.sha256(), 0
            with urlopen(url, timeout=60) as response, destination.open("wb") as stream:
                while chunk := response.read(1024**2):
                    count += len(chunk)
                    if count > 64 * 1024**2:
                        raise ValueError("inventory-runtime-download-bound")
                    digest.update(chunk)
                    stream.write(chunk)
            if digest.hexdigest() != expected:
                raise ValueError("inventory-runtime-package-digest-mismatch")
            return
        except (HTTPError, URLError) as error:
            if isinstance(error, HTTPError) and error.code not in {408, 429, 500, 502, 503, 504}:
                raise
            if attempt == 2:
                raise
            time.sleep(attempt + 1)


def prepare(pins, output, architecture=None, mirror_only=False):
    value = json.loads(pins.read_text())
    architecture = architecture or platform.machine()
    validate(value, architecture)
    output.mkdir(parents=True, exist_ok=False)
    for name in ("nodejs", "npm"):
        row = value["packages"][name]
        filename = name + "-" + package_version(row, architecture) + ".apk"
        mirror = f"{RELEASES}/{release_tag(value)}/{architecture}-{filename}"
        source = f"https://dl-cdn.alpinelinux.org/alpine/v{value['alpine']}/{row['repository']}/{architecture}/{filename}"
        try:
            download(mirror, output / filename, row["sha256"][architecture])
        except HTTPError as error:
            if error.code != 404 or mirror_only:
                raise
            try:
                download(source, output / filename, row["sha256"][architecture])
            except HTTPError as error:
                raise ValueError(f"inventory-runtime-input-unavailable: {architecture}/{filename}; "
                                 "retain approved APKs before Alpine removes them, or review fresh pins") from error


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pins", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--architecture", choices=sorted(ARCHITECTURES))
    parser.add_argument("--mirror-only", action="store_true")
    parser.add_argument("--release-tag", action="store_true")
    args = parser.parse_args()
    if args.release_tag:
        print(release_tag(json.loads(args.pins.read_text())))
    else:
        if args.output is None:
            parser.error("--output is required")
        prepare(args.pins, args.output, args.architecture, args.mirror_only)
