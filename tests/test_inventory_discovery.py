"""Observed filesystem and input-disposition contracts, no application DSNs."""

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path

import pytest

from sourcebastion.inventory import discover
from sourcebastion.inventory.inputs import InputRefusal, Limits, Source
from sourcebastion.inventory.registry import DiscoveryConfig, format_for


def write(root, path, content):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content.encode() if isinstance(content, str) else content)
    return target


def run(root, config=None, limits=None):
    with Source(root, limits) as source:
        result = discover(source, config=config)
        return result, {r.path: r for r in result.inputs}


@pytest.mark.parametrize(
    "name", ["requirements.txt", "deploy.in", "deps.pip", ".github/python-locks/custom.txt", "scripts/python-build.in"]
)
def test_custom_and_hidden_requirements(name, tmp_path):
    content = "pip==26.0.1 --hash=sha256:" + "a" * 64 + "\n"
    write(tmp_path, name, content)
    result, rows = run(tmp_path)
    assert result.status == "complete"
    assert rows[name].disposition == "parsed"
    assert rows[name].sha256 == hashlib.sha256(content.encode()).hexdigest()
    assert result.documents[0].requirements[0].name == "pip"
    assert result.to_dict()["registry_version"] == "sourcebastion.inventory-registry/1"


def test_includes_constraints_dedup_and_context_provenance(tmp_path):
    write(tmp_path, "requirements.txt", "-r nested/base.config\n-r nested/base.config\n-c constraints.txt\n")
    write(tmp_path, "nested/base.config", "requests\n-c ../constraints.txt\n")
    write(tmp_path, "constraints.txt", "requests==2.32.3\n")
    result, rows = run(tmp_path)
    assert result.status == "complete"
    assert rows["nested/base.config"].disposition == "parsed"
    assert ("requirements.txt", "nested/base.config", "requirement") in result.contexts
    assert ("requirements.txt", "constraints.txt", "constraint") in result.contexts
    assert len([d for d in result.documents if d.path == "nested/base.config"]) == 1
    assert [(r.line, r.kind, r.target) for r in result.references if r.source == "requirements.txt"] == [
        (1, "include", "nested/base.config"),
        (2, "include", "nested/base.config"),
        (3, "constraint", "constraints.txt"),
    ]
    # These are located source declarations; discovery does not emit selected
    # dependencies or invent an installed relationship for constraint records.
    assert not hasattr(result, "packages") and not hasattr(result, "edges")


def test_explicit_include_upgrades_ambiguous_candidate(tmp_path):
    write(tmp_path, "requirements.txt", "-r bare.txt\n")
    write(tmp_path, "bare.txt", "requests\n")
    result, rows = run(tmp_path)
    assert rows["bare.txt"].disposition == "parsed"
    assert next(d for d in result.documents if d.path == "bare.txt").requirements[0].exact_version is None


@pytest.mark.parametrize(
    "target",
    [
        "../private.txt",
        "/etc/passwd",
        "https://user:secret@example.invalid/a.txt",
        "file:///etc/passwd",
        "//user:secret@example.invalid/private.txt",
        r"\\user:secret@example.invalid\private.txt",
    ],
)
def test_escaped_includes_refuse_without_read_or_credentials(target, tmp_path):
    write(tmp_path, "requirements.txt", "-r " + target + "\n")
    result, rows = run(tmp_path)
    assert result.status == "partial"
    assert rows["requirements.txt"].disposition == "failed"
    assert len(rows) == 1
    assert "secret" not in json.dumps(result.to_dict())


def test_symlink_and_fifo_never_open(tmp_path):
    write(tmp_path, "outside.txt", "private==99\n")
    root = tmp_path / "source"
    root.mkdir()
    (root / "requirements.txt").symlink_to("../outside.txt")
    os.mkfifo(root / "queue.pip")
    result, rows = run(root)
    assert result.status == "partial" and not result.documents
    assert rows["requirements.txt"].reason == "unsupported-symlink"
    assert rows["queue.pip"].reason == "unsupported-special"


def test_cycle_has_located_refusal(tmp_path):
    write(tmp_path, "requirements.txt", "-r b.pip\n")
    write(tmp_path, "b.pip", "-r requirements.txt\n")
    result, _ = run(tmp_path)
    assert result.status == "partial"
    assert any(r.reason == "include-cycle" and r.line == 1 for r in result.references)


@pytest.mark.parametrize(
    "content,disposition",
    [
        ("Please discuss packages tomorrow.\n", "ignored"),
        ("requests\n", "ignored"),
        ("requests==2.32.3\nBAD PROSE\n", "failed"),
        ("", "ignored"),
    ],
)
def test_ordinary_text_does_not_become_dependencies(content, disposition, tmp_path):
    write(tmp_path, "notes.txt", content)
    result, rows = run(tmp_path)
    assert rows["notes.txt"].disposition == disposition
    assert not result.documents[0].requirements


def test_ignore_is_explicit_and_includes_cannot_bypass_it(tmp_path):
    write(tmp_path, ".git/requirements.txt", "private==1\n")
    write(tmp_path, ".hidden/requirements.txt", "pip==26.0.1\n")
    write(tmp_path, "vendor/requirements.txt", "private==2\n")
    write(tmp_path, "requirements.txt", "-r vendor/requirements.txt\n-r .git/requirements.txt\n")
    result, rows = run(tmp_path, DiscoveryConfig(ignored=("vendor",)))
    assert rows[".hidden/requirements.txt"].disposition == "parsed"
    assert rows[".git"].disposition == rows["vendor"].disposition == "ignored"
    assert all(r.disposition == "ignored" for r in result.references)
    assert not any(d.path.startswith(("vendor/", ".git/")) for d in result.documents)


def test_explicit_mapping_is_data_and_missing_paths_stay_visible(tmp_path):
    write(tmp_path, "deployment/dependencies.cfg", "requests\n")
    config = DiscoveryConfig(
        mappings=(("deployment/dependencies.cfg", "pip-requirements"), ("missing.cfg", "pip-requirements"))
    )
    result, rows = run(tmp_path, config)
    assert rows["deployment/dependencies.cfg"].disposition == "parsed"
    assert rows["missing.cfg"].disposition == "failed" and result.status == "partial"
    assert result.config_sha256 == config.sha256


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(mappings=(("../outside", "pip-requirements"),)),
        dict(mappings=(("x", "exec"),)),
        dict(mappings=(("x", "pip-requirements"), ("x", "npm-lock"))),
        dict(ignored=("../x",)),
        dict(include_depth=65),
        dict(include_targets=4097),
        dict(semantic_checks=5000001),
    ],
)
def test_invalid_configuration_cannot_expand_authority(kwargs):
    with pytest.raises((ValueError, InputRefusal)):
        DiscoveryConfig(**kwargs)


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(entries=100001),
        dict(depth=65),
        dict(file_bytes=2097153),
        dict(total_bytes=268435457),
        dict(wall_seconds=151),
        dict(entries=True),
    ],
)
def test_ceiling_increases_rejected(kwargs):
    with pytest.raises(ValueError):
        Limits(**kwargs)


def test_discovery_limits_are_visible_and_keep_safe_sibling(tmp_path):
    write(tmp_path, "a/b/requirements.txt", "pip==26.0.1\n")
    write(tmp_path, "requirements.txt", "pip==26.0.1\n")
    result, rows = run(tmp_path, limits=Limits(depth=1))
    assert result.status == "partial"
    assert rows["a/b"].disposition == "bounded-omission"
    assert rows["requirements.txt"].disposition == "parsed"
    result, rows = run(tmp_path, limits=Limits(entries=1))
    assert result.status == "partial" and "input-traversal-budget-exceeded" in result.refusal_codes


def test_include_limits_and_deterministic_repetition(tmp_path):
    write(tmp_path, "requirements.txt", "-r a.config\n-r b.config\n")
    write(tmp_path, "a.config", "-r b.config\n")
    write(tmp_path, "b.config", "pip==26.0.1\n")
    for config, code in [
        (DiscoveryConfig(include_targets=1), "include-target-budget-exceeded"),
        (DiscoveryConfig(include_depth=1), "include-depth-budget-exceeded"),
    ]:
        first, _ = run(tmp_path, config)
        second, _ = run(tmp_path, config)
        assert first == second and first.status == "partial"
        assert any(r.reason == code for r in first.references)


def test_changed_source_cannot_supply_documents(tmp_path, monkeypatch):
    path = write(tmp_path, "requirements.txt", "pip==26.0.1\n")
    with Source(tmp_path) as source:
        real_validate = source.validate

        def mutate():
            path.write_text("pip==26.2\n")
            real_validate()

        monkeypatch.setattr(source, "validate", mutate)
        result = discover(source)
        assert result.status == "failed" and not result.documents
        assert any(code.startswith("changed-") for code in result.refusal_codes)


def test_deadline_is_failed_instead_of_valid_empty_inventory(tmp_path):
    with Source(tmp_path) as source:
        source.deadline = 0
        result = discover(source)
        assert result.status == "failed" and result.refusal_codes == ("input-deadline-exceeded",)


def test_known_ecosystems_remain_unsupported_until_adapted(tmp_path):
    for path in [
        "pyproject.toml",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "go.mod",
        "Cargo.lock",
        "pom.xml",
        "Gemfile.lock",
        "composer.lock",
        "packages.lock.json",
    ]:
        write(tmp_path, path, "unparsed synthetic input\n")
    result, rows = run(tmp_path)
    assert result.status == "partial"
    assert len(rows) == 10 and all(r.disposition == "unsupported" and r.sha256 for r in rows.values())


def test_real_project_custom_python_paths(tmp_path):
    root = Path(__file__).resolve().parents[1]
    for name in [
        "scripts/python-build.in",
        ".github/python-locks/build-cp314-musllinux_1_2_x86_64.txt",
        ".github/python-locks/runtime-cp314-musllinux_1_2_x86_64.txt",
    ]:
        write(tmp_path, name, (root / name).read_bytes())
    result, rows = run(tmp_path)
    assert result.status == "complete" and len(result.documents) == 3
    assert all(r.disposition == "parsed" for r in rows.values())
    assert all(d.requirements for d in result.documents)


CORPUS = json.loads((Path(__file__).parent / "fixtures/inventory/corpus.json").read_text())


@pytest.mark.parametrize("fixture", CORPUS, ids=lambda c: c["id"])
def test_frozen_s01_inputs_are_located_without_source_mutation(fixture, tmp_path):
    for path, content in fixture["files"].items():
        write(tmp_path, path, content)
    for path, target in fixture["symlinks"].items():
        link = tmp_path / path
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target)
    before = {p: (tmp_path / p).read_bytes() for p in fixture["files"]}
    result, rows = run(tmp_path)
    assert result == run(tmp_path)[0]
    assert before == {p: (tmp_path / p).read_bytes() for p in fixture["files"]}
    for path in fixture["files"]:
        # Input discovery has no package/edge assertions: those remain S03.
        if format_for(path, DiscoveryConfig()):
            assert path in rows
    for path in fixture["symlinks"]:
        assert rows[path].reason == "unsupported-symlink"


def test_uncached_read_mutation_invalidates_earlier_documents(tmp_path, monkeypatch):
    write(tmp_path, "a.txt", "pip==26.0.1\n")
    target = write(tmp_path, "b.txt", "pip==26.0.1\n")
    original_read = os.read
    changed = False

    def mutate(descriptor, count):
        nonlocal changed
        chunk = original_read(descriptor, count)
        if chunk and not changed and os.fstat(descriptor).st_ino == target.stat().st_ino:
            target.write_text("pip==26.2\n")
            changed = True
        return chunk

    with Source(tmp_path) as source:
        monkeypatch.setattr(os, "read", mutate)
        result = discover(source)
        assert changed and result.status == "failed" and not result.documents
        assert "changed-input-bytes" in result.refusal_codes
        assert "a.txt" in source.cache and "b.txt" not in source.cache
