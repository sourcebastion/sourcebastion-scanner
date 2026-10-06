"""Archive descriptor-bound snapshots; preserve synthetic links as data only."""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile


def metadata_key(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def read_regular(name, parent_fd, expected, remaining):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or metadata_key(before) != metadata_key(expected):
            raise ValueError("evidence file changed before snapshot")
        # One bounded immutable byte snapshot feeds BOTH archive and checksum.
        if before.st_size > min(64 * 1024 * 1024, remaining):
            raise ValueError("raw evaluation archive exceeds declared byte budget")
        content = bytearray()
        while len(content) < before.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, before.st_size - len(content)))
            if not chunk:
                raise ValueError("evidence file changed during snapshot")
            content.extend(chunk)
        if os.read(descriptor, 1) or metadata_key(os.fstat(descriptor)) != metadata_key(before):
            raise ValueError("evidence file changed during snapshot")
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if metadata_key(current) != metadata_key(before):
            raise ValueError("evidence path changed during snapshot")
        return bytes(content)
    finally:
        os.close(descriptor)


def pack(roots, output, max_bytes=1024 * 1024 * 1024):
    if any("/" in label or label in {"", ".", "..", "SYMLINKS.json", "SHA256SUMS", "ARCHIVE.json"} for label in roots):
        raise ValueError("invalid archive label")
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    partial = output.with_name(output.name + ".partial")
    checksums, links, missing = [], {}, []
    total, file_count = 0, 0

    def add(archive, name, content):
        checksums.append(f"{hashlib.sha256(content).hexdigest()}  {name}\n")
        info = tarfile.TarInfo(name)
        info.size, info.mode = len(content), 0o644
        archive.addfile(info, io.BytesIO(content))

    def visit(archive, directory_fd, prefix):
        nonlocal total, file_count
        for name in sorted(os.listdir(directory_fd)):
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            member = f"{prefix}/{name}"
            if stat.S_ISLNK(info.st_mode):
                links[member] = os.readlink(name, dir_fd=directory_fd)
            elif stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
                try:
                    if metadata_key(os.fstat(child)) != metadata_key(info):
                        raise ValueError("evidence directory changed before traversal")
                    visit(archive, child, member)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                content = read_regular(name, directory_fd, info, max_bytes - total)
                total += len(content)
                file_count += 1
                add(archive, member, content)
            else:
                raise ValueError("non-regular evidence file")

    with (
        partial.open("xb") as destination,
        gzip.GzipFile(fileobj=destination, mode="wb", filename="", mtime=0) as compressed,
    ):
        with tarfile.open(fileobj=compressed, mode="w|") as archive:
            for label, root in sorted(roots.items()):
                try:
                    info = root.lstat()
                except FileNotFoundError:
                    missing.append(label)
                    continue
                if stat.S_ISREG(info.st_mode):
                    content = read_regular(str(root), None, info, max_bytes - total)
                    total += len(content)
                    file_count += 1
                    add(archive, label, content)
                elif stat.S_ISDIR(info.st_mode):
                    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        if metadata_key(os.fstat(descriptor)) != metadata_key(info):
                            raise ValueError("evidence root changed before traversal")
                        visit(archive, descriptor, label)
                    finally:
                        os.close(descriptor)
                else:
                    raise ValueError("non-regular or symlink evidence root")
            add(archive, "SYMLINKS.json", (json.dumps(links, sort_keys=True, indent=2) + "\n").encode())
            metadata = {
                "schema_version": 1,
                "missing_roots": missing,
                "regular_files": file_count,
                "links_as_data": len(links),
                "raw_bytes": total,
            }
            add(archive, "ARCHIVE.json", (json.dumps(metadata, sort_keys=True, indent=2) + "\n").encode())
            content = "".join(checksums).encode()
            info = tarfile.TarInfo("SHA256SUMS")
            info.size, info.mode = len(content), 0o644
            archive.addfile(info, io.BytesIO(content))
    # Promote complete evidence without overwriting any previous artifact.
    os.link(partial, output)
    partial.unlink()
    with output.open("rb") as handle:
        checksum = hashlib.file_digest(handle, "sha256").hexdigest()
    output.with_suffix(output.suffix + ".sha256").write_text(f"{checksum}  {output.name}\n")
    return {**metadata, "archive_sha256": checksum}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", action="append", required=True, help="LABEL=PATH")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    roots = dict(argument.split("=", 1) for argument in args.root)
    if len(roots) != len(args.root):
        raise ValueError("duplicate archive label")
    print(json.dumps(pack({label: Path(path) for label, path in roots.items()}, args.output)))
