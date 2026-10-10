"""Release Python updates verify compatibility before changing reviewed pins."""
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
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
    (tmp_path / "images/Dockerfile").write_text((ROOT / "images/Dockerfile").read_text())
    (tmp_path / ".github/python-locks").mkdir(parents=True)
    (tmp_path / ".github/python-locks/old.txt").write_text("reviewed")
    (tmp_path / ".github/semgrep-artifacts.json").write_text("{}")
    for name in ("base-image-pins.json", "inventory-runtime-pins.json"):
        (tmp_path / ".github" / name).write_bytes((ROOT / ".github" / name).read_bytes())
    base = versions.base_tools()
    monkeypatch.setattr(base, "resolve", lambda version, alpine: (
        f"{version}-alpine{alpine}", "sha256:" + "a" * 64,
        {"amd64": "sha256:" + "b" * 64, "arm64": "sha256:" + "c" * 64}))
    monkeypatch.setattr(versions, "base_tools", lambda: base)
    monkeypatch.setattr(versions, "ROOT", tmp_path)
    return tmp_path


def test_release_input_cannot_override_the_reviewed_source(reviewed):
    assert versions.current("3.14.8") == "3.14.8"
    with pytest.raises(ValueError, match="reviewed source"):
        versions.current("3.15.0")
    (reviewed / "images/Dockerfile").write_text("ARG PYTHON_VERSION=3.15.0\n")
    with pytest.raises(ValueError, match="disagree"):
        versions.current()


@pytest.mark.parametrize("requested", ["", " ", "3.14", " 3.14 ", "3.14.8"])
def test_release_resolves_minor_to_exact_reviewed_patch(reviewed, requested):
    assert versions.current(requested) == "3.14.8"


@pytest.mark.parametrize("requested", ["3.1", "3.13", "3.14.9", "3.15"])
def test_release_rejects_other_minor_or_patch(reviewed, requested):
    with pytest.raises(ValueError, match="reviewed source"):
        versions.current(requested)


@pytest.mark.parametrize("requested", ["3", "latest", "3.14rc1", "3.14.*"])
def test_release_rejects_unreviewed_floating_or_preview_input(reviewed, requested):
    with pytest.raises(ValueError, match="3.MINOR"):
        versions.current(requested)


def test_minor_update_stays_in_requested_minor_and_verifies_before_writing(reviewed, monkeypatch):
    metadata = {v: {"version": v, "variants": ["alpine3.23"]}
                for v in ["3.15.0", "3.14.10", "3.14.9", "3.14.8", "3.13.16"]}
    monkeypatch.setattr(versions, "urlopen", lambda *a, **k: io.BytesIO(json.dumps(metadata).encode()))
    state = []
    verified = []

    def generate(lock, target):
        assert verified
        assert versions.current() == "3.14.8"
        if state[-1] == "3.14.10":
            raise ValueError("no compatible wheel")
        (target / "new.txt").write_text("verified wheels")
        (target / "manifest.json").write_text("{}")

    monkeypatch.setattr(versions, "artifact_tools", lambda: SimpleNamespace(
        validate_lock=lambda lock: lock, verify=lambda lock: verified.append(True),
        configure_python=state.append, generate_dependencies=generate))
    assert versions.update(" 3.14 ") == "3.14.9"
    assert state == ["3.14.10", "3.14.9"]
    assert versions.current("3.14") == "3.14.9"


def test_unavailable_minor_preserves_reviewed_files(reviewed, monkeypatch):
    monkeypatch.setattr(versions, "urlopen", lambda *a, **k: io.BytesIO(b"{}"))
    with pytest.raises(ValueError, match="no stable Python candidate"):
        versions.update("3.16")
    assert versions.current() == "3.14.8"
    assert (reviewed / ".github/python-locks/old.txt").read_text() == "reviewed"


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


@pytest.mark.parametrize("requested", ["auto", "", " auto "])
def test_next_patch_comes_from_declared_version_without_changing_files(tmp_path, monkeypatch, requested):
    monkeypatch.setattr(release, "ROOT", tmp_path)
    (tmp_path / "VERSION").write_text("1.7.36\n")
    assert release.resolve_version(requested) == "1.7.37"
    assert (tmp_path / "VERSION").read_text() == "1.7.36\n"
    assert release.resolve_version("1.8.0") == "1.8.0"


def test_automatic_release_cli_uses_generated_notes_and_exact_next_patch(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    script = scripts / "prepare_release.py"
    script.write_text((ROOT / "scripts/prepare_release.py").read_text())
    (tmp_path / "VERSION").write_text("1.7.36\n")
    (tmp_path / "CHANGELOG.md").write_text("## [1.7.36]\n\nPrevious release.\n")
    notes = tmp_path / "notes.md"
    notes.write_text("## What's Changed\n* Accept Python minor versions (#83).\n")
    env = {key: value for key, value in os.environ.items()
           if key not in {"RELEASE_VERSION", "RELEASE_NOTES"}}
    subprocess.run([sys.executable, str(script), "--notes-file", str(notes)], env=env, check=True)
    assert (tmp_path / "VERSION").read_text() == "1.7.37\n"
    changelog = (tmp_path / "CHANGELOG.md").read_text()
    assert "### What's Changed\n* Accept Python minor versions (#83)." in changelog
    assert changelog.index("[1.7.37]") < changelog.index("[1.7.36]")


def test_manual_notes_work_without_generated_file(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    script = scripts / "prepare_release.py"
    script.write_text((ROOT / "scripts/prepare_release.py").read_text())
    (tmp_path / "VERSION").write_text("1.7.36\n")
    (tmp_path / "CHANGELOG.md").write_text("## [1.7.36]\n\nPrevious release.\n")
    env = dict(os.environ, RELEASE_VERSION="1.8.0", RELEASE_NOTES="Reviewed custom release notes.")
    subprocess.run([sys.executable, str(script), "--notes-file", str(tmp_path / "missing")],
                   env=env, check=True)
    assert (tmp_path / "VERSION").read_text() == "1.8.0\n"
    assert "Reviewed custom release notes." in (tmp_path / "CHANGELOG.md").read_text()


def test_python_update_keeps_all_release_pins_coupled(reviewed, monkeypatch):
    monkeypatch.setattr(versions, "urlopen", lambda *a, **k: io.BytesIO(b"{}"))
    monkeypatch.setattr(versions, "artifact_tools", lambda: SimpleNamespace(
        validate_lock=lambda x: x, verify=lambda x: None, configure_python=lambda x: None,
        generate_dependencies=lambda lock, path: (path / "new.txt").write_text("verified")))
    assert versions.update("3.14.9") == "3.14.9"
    base = json.loads((reviewed / ".github/base-image-pins.json").read_text())
    runtime = json.loads((reviewed / ".github/inventory-runtime-pins.json").read_text())
    python = next(row for row in base["images"] if row["name"] == "python")
    assert python["upstream_tag"] == "3.14.9-alpine3.23"
    assert runtime["python"] == versions.current() == "3.14.9"
    assert runtime["python_image"].endswith("@" + python["digest"])
    assert set(runtime["python_native_manifests"]) == {"amd64", "arm64"}
    assert "ARG PYTHON_BASE=docker.io/library/python@" + python["digest"] in (reviewed / "images/Dockerfile").read_text()


def test_registry_failure_keeps_pins_and_wheel_locks_unchanged(reviewed, monkeypatch):
    before = {p.relative_to(reviewed): p.read_bytes() for p in reviewed.rglob("*") if p.is_file()}
    monkeypatch.setattr(versions, "urlopen", lambda *a, **k: io.BytesIO(b"{}"))
    monkeypatch.setattr(versions, "artifact_tools", lambda: SimpleNamespace(
        validate_lock=lambda x: x, verify=lambda x: None, configure_python=lambda x: None,
        generate_dependencies=lambda lock, path: (path / "new.txt").write_text("verified")))
    def refused(*args):
        raise ValueError("python-base-descriptor-mismatch")
    monkeypatch.setattr(versions.base_tools(), "resolve", refused)
    with pytest.raises(ValueError, match="descriptor-mismatch"):
        versions.update("3.14.9")
    assert {p.relative_to(reviewed): p.read_bytes() for p in reviewed.rglob("*") if p.is_file()} == before
