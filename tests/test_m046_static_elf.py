import os
from pathlib import Path
import platform
import struct
import sys

import pytest

from evaluation.m046.static_elf import validate


def elf(kind=1):
    content = bytearray(120)
    content[:7] = b"\x7fELF\x02\x01\x01"
    machine = {"x86_64": 62, "aarch64": 183}[platform.machine()]
    struct.pack_into("<HHI", content, 16, 2, machine, 1)
    struct.pack_into("<Q", content, 32, 64)
    struct.pack_into("<HHH", content, 52, 64, 56, 1)
    struct.pack_into("<IIQQQQQQ", content, 64, kind, 5, 0, 0, 0, 120, 120, 4096)
    return content


def test_static_elf_accepts_bounded_native_load_segment(tmp_path):
    binary = tmp_path / "binary"
    binary.write_bytes(elf())
    assert validate(binary)["load_segments"] == 1


@pytest.mark.parametrize("kind", [2, 3])
def test_static_elf_refuses_dynamic_linkage_and_loader(tmp_path, kind):
    binary = tmp_path / "binary"
    binary.write_bytes(elf(kind))
    with pytest.raises(ValueError, match="dynamic"):
        validate(binary)


@pytest.mark.parametrize("mutation", ["architecture", "count", "offset", "segment", "short", "header"])
def test_static_elf_refuses_untrusted_extents(tmp_path, mutation):
    content = elf()
    if mutation == "architecture":
        struct.pack_into("<H", content, 18, 183 if platform.machine() == "x86_64" else 62)
    elif mutation == "count":
        struct.pack_into("<H", content, 56, 129)
    elif mutation == "offset":
        struct.pack_into("<Q", content, 32, 2**63)
    elif mutation == "segment":
        struct.pack_into("<Q", content, 64 + 32, 121)
    elif mutation == "short":
        content = content[:-1]
    else:
        content[4] = 1
    binary = tmp_path / "binary"
    binary.write_bytes(content)
    with pytest.raises(ValueError):
        validate(binary)


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_static_elf_refuses_special_files_without_blocking(tmp_path, kind):
    binary = tmp_path / "binary"
    if kind == "symlink":
        binary.symlink_to(Path(sys.executable).resolve())
    else:
        os.mkfifo(binary)
    with pytest.raises((ValueError, OSError)):
        validate(binary)


def test_static_elf_refuses_real_dynamic_interpreter():
    with pytest.raises(ValueError, match="dynamic"):
        validate(Path(sys.executable).resolve())
