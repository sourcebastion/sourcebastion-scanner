"""Installed binaries and all notice files must match the reviewed source tree."""
import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("inventory_packaging", ROOT / "scripts/verify-inventory-packaging.py")
packaging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packaging)


@pytest.fixture
def image(tmp_path):
    original, retained = tmp_path / "original", tmp_path / "retained"
    for directory in (original, retained):
        directory.mkdir()
        (directory / "SOURCE-AVAILABILITY.md").write_text("source directions")
        (directory / "LICENSE").write_text("original license")
    library = tmp_path / "example.libs/libexample.so.1"
    library.parent.mkdir()
    raw = b"\x7fELFbinary"
    library.write_bytes(raw)
    dist = SimpleNamespace(metadata={"Name": "example"}, version="1.0",
                           files=[Path("example.libs/libexample.so.1")],
                           locate_file=lambda name: tmp_path / name)
    expected = [{"distribution": "example", "version": "1.0", "path": "example.libs/libexample.so.1",
                 "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}]
    return dist, expected, retained, original, library


def test_installed_closure_matches_original_bytes(image):
    dist, expected, retained, original, _ = image
    result = packaging.native_distribution_closure([dist], expected, retained, original)
    assert result["libraries"] == expected
    assert set(result["notice_files"]) == {"LICENSE", "SOURCE-AVAILABILITY.md"}


@pytest.mark.parametrize("change", ["library-bytes", "version", "new-library", "missing-library", "source-directions", "license", "symlink"])
def test_installed_change_refuses(image, change):
    dist, expected, retained, original, library = image
    if change == "library-bytes":
        library.write_bytes(b"\x7fELFother!")
    elif change == "version":
        dist.version = "2.0"
    elif change == "new-library":
        other = library.with_name("libextra.so.1")
        other.write_bytes(b"\x7fELFextra")
        dist.files.append(Path("example.libs/libextra.so.1"))
    elif change == "missing-library":
        dist.files = []
    elif change == "source-directions":
        (retained / "SOURCE-AVAILABILITY.md").write_text("different directions")
    elif change == "license":
        (retained / "LICENSE").unlink()
    else:
        (retained / "LICENSE").unlink()
        (retained / "LICENSE").symlink_to(original / "LICENSE")
    with pytest.raises(ValueError, match="installed-native"):
        packaging.native_distribution_closure([dist], expected, retained, original)


def test_wheel_data_purelib_path_maps_to_installed_path(image):
    dist, expected, retained, original, _ = image
    expected[0]["path"] = "example-1.0.data/purelib/" + expected[0]["path"]
    packaging.native_distribution_closure([dist], expected, retained, original)


@pytest.mark.parametrize("available", [False, True])
def test_pending_or_different_source_reference_cannot_qualify(image, available):
    dist, expected, retained, original, _ = image
    reference = "ghcr.io/sourcebastion/sourcebastion-scanner@sha256:" + "a" * 64
    if available:
        for root in (retained, original):
            (root / "SOURCE-AVAILABILITY.md").write_text(reference)
        packaging.native_distribution_closure([dist], expected, retained, original, reference)
    else:
        with pytest.raises(ValueError, match="source-directions-pending-or-mismatched"):
            packaging.native_distribution_closure([dist], expected, retained, original, reference)
