"""Prepare checksum-pinned source archives for the existing GHCR repository.

curl downloads, tar retains original archives, ORAS publishes the OCI artifact.
No downloaded source or build recipe is executed. Publication stays in a
main-only workflow; this module has no registry credentials or write authority.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
PINS = ROOT / ".github/native-source-pins.json"
REPOSITORY = "ghcr.io/sourcebastion/sourcebastion-scanner"
BUNDLE = "native-sources.tar"


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pins(path=PINS, notices=None):
    value = json.loads(path.read_text())
    if value.get("repository") != REPOSITORY:
        raise ValueError("source mirror must use the existing scanner repository")
    for field, pattern in (("bundle_sha256", r"[0-9a-f]{64}"),
                           ("manifest_digest", r"sha256:[0-9a-f]{64}")):
        if not re.fullmatch(pattern, value.get(field, "")):
            raise ValueError("invalid source pin: " + field)
    archives = value.get("archives")
    if not isinstance(archives, list) or not archives:
        raise ValueError("source archives missing")
    names = set()
    for item in archives:
        name = item.get("filename", "")
        url = urlsplit(item.get("url", ""))
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]+", name) or name in names:
            raise ValueError("unsafe or duplicate source filename")
        names.add(name)
        if url.scheme != "https" or not url.hostname or url.username or url.password:
            raise ValueError("source URL must be HTTPS without credentials")
        if not re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", "")):
            raise ValueError("invalid source digest")
        if type(item.get("bytes")) is not int or not 0 < item["bytes"] < 200_000_000:
            raise ValueError("invalid source size")
        if not isinstance(item.get("components"), list) or not item["components"]:
            raise ValueError("source component binding missing")
    if notices is None:
        notices = json.loads((ROOT / "third-party-notices/manifest.json").read_text())
    for component in notices["components"]:
        if not component["license"].startswith(("GPL-", "LGPL-")):
            continue
        if not any(component["id"] in a["components"] and
                   a["url"] == component["source_url"] and
                   a["sha256"] == component["source_sha256"] for a in archives):
            raise ValueError("copyleft source coverage missing: " + component["id"])
    return value


def verify_archives(value, cache):
    for item in value["archives"]:
        path = cache / item["filename"]
        if (path.is_symlink() or not path.is_file() or
                path.stat().st_size != item["bytes"] or sha256(path) != item["sha256"]):
            raise ValueError("source bytes disagree with pin: " + item["filename"])


def download(value, cache):
    cache.mkdir(parents=True, exist_ok=True)
    for item in value["archives"]:
        path = cache / item["filename"]
        if path.exists() or path.is_symlink():
            continue  # Verification below rejects stale or redirected caches.
        temporary = path.with_suffix(path.suffix + ".partial")
        if temporary.exists() or temporary.is_symlink():
            raise ValueError("remove interrupted download before retry: " + str(temporary))
        try:
            subprocess.run(["curl", "--fail", "--location", "--silent", "--show-error",
                            "--proto", "=https", "--proto-redir", "=https",
                            "--retry", "2", "--connect-timeout", "20", "--max-time", "600",
                            "--max-filesize", str(item["bytes"]),
                            "--output", str(temporary), item["url"]], check=True)
            if temporary.stat().st_size != item["bytes"] or sha256(temporary) != item["sha256"]:
                raise ValueError("download disagrees with source pin: " + item["filename"])
            temporary.rename(path)
        finally:
            temporary.unlink(missing_ok=True)
    verify_archives(value, cache)


def build(value, cache, output):
    """Deterministic tar, retaining original compressed archives unmodified."""
    verify_archives(value, cache)
    with tarfile.open(output, "w", format=tarfile.USTAR_FORMAT) as archive:
        sums = "".join(f"{a['sha256']}  {a['filename']}\n"
                       for a in sorted(value["archives"], key=lambda a: a["filename"]))
        info = tarfile.TarInfo("SHA256SUMS")
        info.size, info.mode = len(sums.encode()), 0o644
        archive.addfile(info, io.BytesIO(sums.encode()))
        for item in sorted(value["archives"], key=lambda a: a["filename"]):
            info = tarfile.TarInfo(item["filename"])
            info.size, info.mode = item["bytes"], 0o644
            with (cache / item["filename"]).open("rb") as stream:
                archive.addfile(info, stream)
    return sha256(output)


def verify_bundle(value, path):
    if path.is_symlink() or sha256(path) != value["bundle_sha256"]:
        raise ValueError("source bundle disagrees with reviewed pin")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify", "reference"))
    parser.add_argument("--directory", type=Path, default=Path("native-sources"))
    args = parser.parse_args()
    value = pins()
    if args.command == "reference":
        print(value["repository"] + "@" + value["manifest_digest"])
        return
    directory = args.directory
    if args.command == "prepare":
        directory.mkdir(parents=True, exist_ok=True)
        download(value, directory / "archives")
        build(value, directory / "archives", directory / BUNDLE)
    verify_bundle(value, directory / BUNDLE)
    print("Verified source bundle sha256:" + value["bundle_sha256"])


if __name__ == "__main__":
    main()
