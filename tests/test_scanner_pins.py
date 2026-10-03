"""Pinned scanner downloads select native binaries and reject tampering."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("downloads", ROOT / "scripts/download_scanners.py")
downloads = importlib.util.module_from_spec(spec)
spec.loader.exec_module(downloads)


def archive(tool, symlink=False):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as handle:
        member = tarfile.TarInfo(tool)
        if symlink:
            member.type = tarfile.SYMTYPE
            member.linkname = "/etc/passwd"
            handle.addfile(member)
        else:
            member.size = 6
            handle.addfile(member, io.BytesIO(b"binary"))
    return buffer.getvalue()


@pytest.mark.parametrize("tool,owner", [("gitleaks", "gitleaks"), ("grype", "anchore")])
@pytest.mark.parametrize("machine,arches", [("x86_64", {"gitleaks": "x64", "grype": "amd64"}),
                                           ("aarch64", {"gitleaks": "arm64", "grype": "arm64"})])
def test_native_downloads_verify_archive_before_extracting(tool, owner, machine, arches, tmp_path, monkeypatch):
    data = archive(tool)
    arch = arches[tool]
    pins = {tool: {"version": "1.2.3", f"linux_{arch}_sha256": hashlib.sha256(data).hexdigest()}}
    calls = []

    def fetch(url, **kwargs):
        calls.append(url)
        return io.BytesIO(data)

    monkeypatch.setattr(downloads, "urlopen", fetch)
    downloads.download_tool(tool, pins, machine, tmp_path)
    assert calls == [f"https://github.com/{owner}/{tool}/releases/download/v1.2.3/{tool}_1.2.3_linux_{arch}.tar.gz"]
    assert (tmp_path / tool).read_bytes() == b"binary"
    assert (tmp_path / tool).stat().st_mode & 0o777 == 0o755


def test_tampered_archive_cannot_create_a_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(downloads, "urlopen", lambda *a, **k: io.BytesIO(archive("grype")))
    pins = {"grype": {"version": "1.2.3", "linux_amd64_sha256": "0" * 64}}
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        downloads.download_tool("grype", pins, "x86_64", tmp_path)
    assert not list(tmp_path.iterdir())


def test_binary_must_not_be_an_archive_symlink(tmp_path, monkeypatch):
    data = archive("grype", symlink=True)
    monkeypatch.setattr(downloads, "urlopen", lambda *a, **k: io.BytesIO(data))
    pins = {"grype": {"version": "1.2.3", "linux_amd64_sha256": hashlib.sha256(data).hexdigest()}}
    with pytest.raises(ValueError, match="regular binary"):
        downloads.download_tool("grype", pins, "x86_64", tmp_path)
    assert not list(tmp_path.iterdir())
