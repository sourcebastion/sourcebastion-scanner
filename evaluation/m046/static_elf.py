"""Bounded native ELF64 check for the separate CGO-disabled runtime experiment."""

import os
from pathlib import Path
import platform
import stat
import struct


def validate(path):
    descriptor = os.open(Path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 64 <= before.st_size <= 256 * 1024 * 1024:
            raise ValueError("bounded regular ELF required")
        header = os.read(descriptor, 64)
        if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
            raise ValueError("ELF64 little-endian version 1 required")
        kind, machine, version = struct.unpack_from("<HHI", header, 16)
        native = {"x86_64": 62, "aarch64": 183}.get(platform.machine())
        offset = struct.unpack_from("<Q", header, 32)[0]
        header_size, entry_size, count = struct.unpack_from("<HHH", header, 52)
        if (
            native is None
            or machine != native
            or kind not in {2, 3}
            or version != 1
            or header_size != 64
            or entry_size != 56
            or not 1 <= count <= 128
            or offset < 64
            or offset + entry_size * count > before.st_size
        ):
            raise ValueError("invalid or non-native ELF program headers")
        os.lseek(descriptor, offset, os.SEEK_SET)
        headers = os.read(descriptor, entry_size * count)
        if len(headers) != entry_size * count:
            raise ValueError("truncated ELF program headers")
        loads = 0
        for index in range(count):
            record = headers[index * entry_size : (index + 1) * entry_size]
            program_type = struct.unpack_from("<I", record)[0]
            if program_type in {2, 3}:
                raise ValueError("dynamic loader or dynamic linkage is forbidden in static profile")
            file_offset, _virtual, _physical, file_bytes, memory_bytes = struct.unpack_from("<QQQQQ", record, 8)
            if file_offset + file_bytes > before.st_size or (program_type == 1 and memory_bytes < file_bytes):
                raise ValueError("invalid ELF segment extent")
            loads += program_type == 1
        after = os.fstat(descriptor)
        key = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if not loads or key(before) != key(after) or key(before) != key(os.stat(path, follow_symlinks=False)):
            raise ValueError("ELF identity changed or load segments missing")
        return {
            "machine": machine,
            "program_headers": count,
            "load_segments": loads,
            "bytes": before.st_size,
            "dynamic_loader": False,
            "dynamic_linkage": False,
        }
    finally:
        os.close(descriptor)
