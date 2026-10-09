"""Conservative source lock enumeration, graph losses and whole-input refusals."""

import importlib.util
import json
from pathlib import Path
import subprocess

import pytest

from sourcebastion.inventory import compose_secondary_locks
from sourcebastion.inventory.compose_source import compose_source
from sourcebastion.inventory.contract import InventoryLimits, Producer, canonical_bytes
from sourcebastion.inventory.inputs import Source
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256

RUBY = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.1.7)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack\n\nBUNDLED WITH\n   2.5.19\n"
PHP = {
    "content-hash": "a" * 32,
    "packages": [{"name": "psr/log", "version": "3.0.2", "type": "library"}],
    "packages-dev": [],
}


def run(root, *, limits=None):
    config = DiscoveryConfig()
    with Source(root) as source:
        return compose_source(
            source,
            source_sha256="a" * 64,
            producer=Producer(
                name="test",
                version="1",
                code_sha256="a" * 64,
                registry_sha256=REGISTRY_SHA256,
                config_sha256=config.sha256,
            ),
            limits=limits,
        )


@pytest.mark.parametrize("case,name,version", [("ruby-lock", "rack", "3.1.7"), ("php-lock", "psr/log", "3.0.2")])
def test_original_source_fixture_matches_hand_authored_records(tmp_path, case, name, version):
    checkout = Path(__file__).resolve().parents[1]
    expected = next(
        c
        for c in json.loads((checkout / "evaluation/m046/canonical-source-expectations-v1.json").read_text())["cases"]
        if c["case"] == case
    )
    for row in expected["fixture_files"]:
        (tmp_path / row["path"]).write_text(row["utf8"])
    result = run(tmp_path)
    assert [(p.name, p.selected_version) for p in result.occurrences] == [(name, version)]
    spec = importlib.util.spec_from_file_location(
        "secondary_comparator", checkout / "scripts/verify-inventory-expectations.py"
    )
    comparator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(comparator)
    comparator.compare(expected, json.loads(canonical_bytes(result)))
    assert canonical_bytes(run(tmp_path)) == canonical_bytes(result)


def test_multiple_roots_and_runtime_development_scopes_remain_separate(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("project execution"))
    for name in ("one", "two"):
        root = tmp_path / name
        root.mkdir()
        (root / "Gemfile.lock").write_text(RUBY)
        data = {**PHP, "packages-dev": [{"name": "vendor/dev", "version": "v1.0.0"}]}
        (root / "composer.lock").write_text(json.dumps(data))
    result = run(tmp_path)
    assert len(result.occurrences) == len({p.id for p in result.occurrences}) == 6
    assert len(result.analysis_scopes) == 4 and not result.roots and not result.relationships
    assert all(
        p.directness == p.activation == "unknown" and p.root_id is p.installed_environment_id is None
        for p in result.occurrences
    )
    assert {p.scopes for p in result.occurrences if p.ecosystem == "composer"} == {("runtime",), ("development",)}


@pytest.mark.parametrize(
    "name,content",
    [
        ("Gemfile.lock", RUBY.replace("    rack (3.1.7)", "    rack (3.1.7)\n      missing (>= 1)")),
        (
            "composer.lock",
            json.dumps({**PHP, "packages": [{**PHP["packages"][0], "require": {"vendor/missing": "^1"}}]}),
        ),
    ],
)
def test_graph_controls_retain_located_loss_without_fabricating_edge(tmp_path, name, content):
    (tmp_path / name).write_text(content)
    result = run(tmp_path)
    assert len(result.occurrences) == 1 and not result.relationships and not result.dependency_selectors
    (loss,) = result.losses
    assert loss.dimension == "graph" and loss.occurrence_id == result.occurrences[0].id
    assert result.coverage.graph == "partial" and result.stages.inventory == "partial"


@pytest.mark.parametrize(
    "content",
    [
        RUBY.replace("GEM", "GIT", 1),
        RUBY + "GEM\n  remote: https://example.invalid/\n  specs:\n",
        RUBY.replace("3.1.7", "3.1.7-x86_64-linux"),
        RUBY.replace("  ruby", "  x86_64-linux"),
        RUBY.replace("  specs:\n", ""),
        RUBY.replace("    rack (3.1.7)", "    rack (3.1.7)\n    rack (3.1.8)"),
        RUBY.replace("   2.5.19", "   malicious command"),
        RUBY + "UNKNOWN\n  secret\n",
    ],
)
def test_unsupported_ruby_source_cannot_admit_a_selected_prefix(tmp_path, content):
    (tmp_path / "Gemfile.lock").write_text(content)
    result = run(tmp_path)
    assert not result.occurrences and result.stages.inventory == "partial"
    assert b"secret" not in canonical_bytes(result)


@pytest.mark.parametrize("version", ["dev-main", "1.x-dev", "3.0.2-beta.1", "https://user:secret@host"])
def test_unassessed_php_versions_never_become_selected(tmp_path, version):
    (tmp_path / "composer.lock").write_text(json.dumps({**PHP, "packages": [{"name": "psr/log", "version": version}]}))
    result = run(tmp_path)
    assert not result.occurrences and result.stages.inventory == "partial"
    assert b"secret" not in canonical_bytes(result)


def test_duplicate_php_package_refuses_whole_input(tmp_path):
    (tmp_path / "composer.lock").write_text(json.dumps({**PHP, "packages-dev": PHP["packages"]}))
    result = run(tmp_path)
    assert not result.occurrences and result.coverage.inputs[0].reason == "duplicate-composer-locked-package"


def test_php_platform_and_branch_alias_controls_do_not_claim_completeness(tmp_path):
    (tmp_path / "composer.lock").write_text(json.dumps({**PHP, "platform": {"php": "^8"}, "aliases": [{"alias": "3"}]}))
    result = run(tmp_path)
    assert len(result.occurrences) == 1 and result.stages.inventory == "partial"
    assert result.coverage.inputs[0].reason == "unassessed-composer-selection-controls"


def test_ruby_registry_credentials_are_hashed_without_disclosure(tmp_path):
    (tmp_path / "Gemfile.lock").write_text(
        RUBY.replace("https://rubygems.org/", "https://user:secret@private.invalid/")
    )
    result = run(tmp_path)
    assert len(result.occurrences) == 1 and result.occurrences[0].registry_source_sha256 is not None
    assert b"secret" not in canonical_bytes(result) and b"private.invalid" not in canonical_bytes(result)


@pytest.mark.parametrize("name,content", [("Gemfile.lock", RUBY), ("composer.lock", json.dumps(PHP))])
def test_global_quota_refusal_clears_prior_python_records(tmp_path, name, content):
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    (tmp_path / name).write_text(content)
    result = run(tmp_path, limits=InventoryLimits(occurrences=1))
    assert result.stages.inventory == "failed" and not result.occurrences and not result.declarations


def test_changed_lock_refuses_mixed_inventory(tmp_path, monkeypatch):
    (tmp_path / "composer.lock").write_text(json.dumps(PHP))
    original = compose_secondary_locks.secondary_locks.parse

    def changed(content, fmt, **kwargs):
        value = original(content, fmt, **kwargs)
        (tmp_path / "composer.lock").write_text("{}")
        return value

    monkeypatch.setattr(compose_secondary_locks.secondary_locks, "parse", changed)
    result = run(tmp_path)
    assert result.stages.inventory == "failed" and not result.occurrences
