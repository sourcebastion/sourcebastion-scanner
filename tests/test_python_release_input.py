"""Release Python updates verify compatibility before changing reviewed pins."""
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("python_release", ROOT / "scripts/python_version.py")
versions = importlib.util.module_from_spec(spec)
spec.loader.exec_module(versions)
spec = importlib.util.spec_from_file_location("release_prepare", ROOT / "scripts/prepare_release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def test_latest_selection_excludes_preview_versions_and_wrong_base():
    metadata = {
        "stable": {"version": "3.14.8", "variants": ["alpine3.23"]},
        "older": {"version": "3.13.16", "variants": ["alpine3.23"]},
        "preview": {"version": "3.15.0rc3", "variants": ["alpine3.23"]},
        "wrong": {"version": "3.16.0", "variants": ["slim-trixie"]},
    }
    assert versions.stable_candidates(metadata) == ["3.14.8", "3.13.16"]


@pytest.fixture
def reviewed(tmp_path, monkeypatch):
    (tmp_path / "images").mkdir()
    (tmp_path / "PYTHON_VERSION").write_text("3.14.8\n")
    (tmp_path / "images/Dockerfile").write_text("ARG PYTHON_VERSION=3.14.8\n")
    (tmp_path / ".github/python-locks").mkdir(parents=True)
    (tmp_path / ".github/python-locks/old.txt").write_text("reviewed")
    (tmp_path / ".github/semgrep-artifacts.json").write_text("{}")
    monkeypatch.setattr(versions, "ROOT", tmp_path)
    return tmp_path


def test_release_input_cannot_override_the_reviewed_source(reviewed):
    assert versions.current("3.14.8") == "3.14.8"
    with pytest.raises(ValueError, match="reviewed source"):
        versions.current("3.15.0")
    (reviewed / "images/Dockerfile").write_text("ARG PYTHON_VERSION=3.15.0\n")
    with pytest.raises(ValueError, match="disagree"):
        versions.current()


def test_latest_uses_newest_compatible_version_and_replaces_old_locks(reviewed, monkeypatch):
    metadata = {v: {"version": v, "variants": ["alpine3.23"]} for v in ["3.15.0", "3.14.9"]}
    monkeypatch.setattr(versions, "urlopen", lambda *a, **k: io.BytesIO(json.dumps(metadata).encode()))
    state = []
    verified = []

    def generate(lock, target):
        assert verified, "publisher verification must happen first"
        if state[-1] == "3.15.0":
            raise ValueError("no compatible wheel")
        (target / "new.txt").write_text("verified for both architectures")
        (target / "manifest.json").write_text("{}")

    monkeypatch.setattr(versions, "artifact_tools", lambda: SimpleNamespace(
        validate_lock=lambda lock: lock, verify=lambda lock: verified.append(True),
        configure_python=state.append, generate_dependencies=generate))
    assert versions.update("latest") == "3.14.9"
    assert state == ["3.15.0", "3.14.9"]
    assert versions.current() == "3.14.9"
    assert not (reviewed / ".github/python-locks/old.txt").exists()


def test_failed_compatibility_check_preserves_reviewed_files(reviewed, monkeypatch):
    monkeypatch.setattr(versions, "urlopen", lambda *a, **k: io.BytesIO(b"{}"))

    def fail(lock, target):
        (target / "partial.txt").write_text("partial")
        raise ValueError("no compatible wheel")

    monkeypatch.setattr(versions, "artifact_tools", lambda: SimpleNamespace(
        validate_lock=lambda lock: lock, verify=lambda lock: None,
        configure_python=lambda version: None, generate_dependencies=fail))
    with pytest.raises(ValueError, match="no compatible wheel"):
        versions.update("3.15.0")
    assert versions.current() == "3.14.8"
    assert (reviewed / ".github/python-locks/old.txt").read_text() == "reviewed"
    assert not (reviewed / ".github/python-locks/partial.txt").exists()


def test_release_preparation_inserts_reviewed_notes_and_rejects_reused_version(tmp_path, monkeypatch):
    monkeypatch.setattr(release, "ROOT", tmp_path)
    (tmp_path / "VERSION").write_text("1.7.36\n")
    (tmp_path / "CHANGELOG.md").write_text("# Changelog\n\n## [1.7.36]\n\nPrevious release.\n")
    release.prepare("1.7.37", "Consolidate scanner images and refresh Python.")
    assert (tmp_path / "VERSION").read_text() == "1.7.37\n"
    text = (tmp_path / "CHANGELOG.md").read_text()
    assert text.index("[1.7.37]") < text.index("[1.7.36]")
    with pytest.raises(ValueError, match="must increase"):
        release.prepare("1.7.37", "Attempted duplicate release.")
