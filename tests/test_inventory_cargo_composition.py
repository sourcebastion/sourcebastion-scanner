"""Located Cargo selectors choose unique source-qualified entries, not purls."""

import pytest
from sourcebastion.inventory.compose_source import compose_source
from sourcebastion.inventory.contract import (
    Producer,
    canonical_bytes,
    InventoryLimits,
    DependencySelector,
    Locator,
    identifier,
)
from sourcebastion.inventory.inputs import Source, InputRefusal
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256

REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
LOCK = f"""version=4
[[package]]
name="alpha"
version="1.2.3"
source="{REGISTRY}"
dependencies=["beta 2.0.0 ({REGISTRY})"]
[[package]]
name="beta"
version="2.0.0"
source="{REGISTRY}"
checksum="{"a"*64}"
"""

SHA = "a" * 64


def run(root, *, config=None, limits=None):
    config = config or DiscoveryConfig()
    with Source(root) as source:
        return compose_source(
            source,
            source_sha256=SHA,
            producer=Producer(
                name="test", version="1", code_sha256=SHA, registry_sha256=REGISTRY_SHA256, config_sha256=config.sha256
            ),
            config=config,
            limits=limits,
        )


def write(root, text=LOCK):
    (root / "Cargo.lock").write_text(text)


def test_exact_qualified_edge_and_null_lock_ownership(tmp_path):
    write(tmp_path)
    result = run(tmp_path)
    assert result.stages.inventory == "complete" and len(result.occurrences) == 2
    assert len(result.dependency_selectors) == len(result.relationships) == 1
    selector = result.dependency_selectors[0]
    assert selector.ecosystem == "cargo" and selector.dialect == "cargo-lock-package-id-3-4"
    assert selector.exact_version == "2.0.0" and selector.declared_range is None
    assert not result.roots and not result.applications
    assert all(
        value.root_id is None and value.directness == "unknown" and value.activation == "unknown"
        for value in result.occurrences
    )
    assert canonical_bytes(result) == canonical_bytes(run(tmp_path))


@pytest.mark.parametrize("reference", ["beta", "beta 2.0.0"])
def test_abbreviated_unique_source_selector_is_supported(tmp_path, reference):
    write(tmp_path, LOCK.replace(f"beta 2.0.0 ({REGISTRY})", reference, 1))
    assert len(run(tmp_path).relationships) == 1


def test_ambiguous_abbreviated_version_never_chooses_by_equal_purl(tmp_path):
    text = LOCK.replace(f"beta 2.0.0 ({REGISTRY})", "beta", 1)
    text += f'\n[[package]]\nname="beta"\nversion="3.0.0"\nsource="{REGISTRY}"\n'
    write(tmp_path, text)
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and len(result.occurrences) == 3 and not result.relationships
    assert result.dependency_selectors[0].reason == "ambiguous-cargo-lock-selector"


def test_duplicate_exact_entry_is_ambiguous_without_deduplication(tmp_path):
    write(tmp_path, LOCK + LOCK[LOCK.index('[[package]]\nname="beta"') :])
    result = run(tmp_path)
    assert len(result.occurrences) == 3 and not result.relationships
    assert result.dependency_selectors[0].reason == "ambiguous-cargo-lock-selector"


def test_source_discriminator_selects_one_of_same_name_version(tmp_path):
    text = LOCK + '\n[[package]]\nname="beta"\nversion="2.0.0"\nsource="registry+https://other.example.invalid/index"\n'
    write(tmp_path, text)
    result = run(tmp_path)
    assert len(result.occurrences) == 3 and len(result.relationships) == 1
    selector = result.dependency_selectors[0]
    child = next(value for value in result.occurrences if value.id == selector.child_id)
    assert selector.registry_source_sha256 == child.registry_source_sha256
    assert len({value.registry_source_sha256 for value in result.occurrences if value.name == "beta"}) == 2


def test_unqualified_selector_cannot_skip_refused_local_identity_blocker(tmp_path):
    text = LOCK.replace(f"beta 2.0.0 ({REGISTRY})", "beta 2.0.0", 1)
    text += '\n[[package]]\nname="beta"\nversion="2.0.0"\n'
    write(tmp_path, text)
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and len(result.occurrences) == 2 and not result.relationships
    assert result.dependency_selectors[0].reason == "ambiguous-cargo-lock-selector"


def test_missing_endpoint_does_not_fallback_to_other_lock_input(tmp_path):
    write(tmp_path, LOCK[: LOCK.index('[[package]]\nname="beta"')])
    child = tmp_path / "other"
    child.mkdir()
    write(child, LOCK[0:10] + LOCK[LOCK.index('[[package]]\nname="beta"') :])
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and not result.relationships


def test_manifest_range_keeps_project_scope_without_selected_packages(tmp_path):
    (tmp_path / "Cargo.toml").write_text('[package]\nname="demo"\nversion="0.1.0"\n[dependencies]\nalpha="1.2.3"\n')
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and not result.occurrences
    assert len(result.roots) == len(result.applications) == len(result.declarations) == 1
    assert result.applications[0].name == "demo" and result.applications[0].version == "0.1.0"
    assert result.declarations[0].declared_range == "1.2.3" and result.declarations[0].exact_version is None
    assert result.declarations[0].root_id == result.roots[0].id
    assert result.coverage.version_resolution == "partial"


def test_malformed_cargo_source_preserves_independent_python_pin(tmp_path):
    write(tmp_path, "version=4\n[[package]]\nname=[]\n")
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and [value.name for value in result.occurrences] == ["pip"]


def test_private_source_is_only_a_hash_or_typed_refusal(tmp_path):
    write(tmp_path, LOCK.replace(REGISTRY, "registry+https://user:secret@example.invalid/index"))
    result = run(tmp_path)
    assert result.stages.inventory == "partial" and not result.occurrences
    assert b"secret" not in canonical_bytes(result)


def test_shared_ledger_refusal_clears_mixed_language_records(tmp_path):
    write(tmp_path)
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    result = run(tmp_path, config=DiscoveryConfig(semantic_checks=80))
    assert result.stages.inventory == "failed" and not result.occurrences and not result.declarations
    assert "composition-check-budget-exceeded" in result.coverage.refusal_codes


def test_global_occurrence_limit_clears_mixed_language_records(tmp_path):
    write(tmp_path)
    (tmp_path / "requirements.txt").write_text("pip==26.0.1\n")
    result = run(tmp_path, limits=InventoryLimits(occurrences=2))
    assert result.stages.inventory == "failed" and not result.occurrences and not result.relationships


def test_final_source_epoch_remains_required(tmp_path, monkeypatch):
    write(tmp_path)

    def changed(self):
        raise InputRefusal("changed-source-input")

    monkeypatch.setattr(Source, "validate", changed)
    result = run(tmp_path)
    assert result.stages.inventory == "failed" and not result.occurrences and not result.relationships


@pytest.mark.parametrize(
    "updates",
    [
        {"dialect": "pep440"},
        {"ecosystem": "pypi"},
        {"declared_range": "^2"},
        {"marker_semantics": "pep508"},
        {"activation": "active"},
        {"extras": ("derive",)},
    ],
)
def test_cargo_lock_selector_cannot_borrow_manifest_or_python_authority(tmp_path, updates):
    write(tmp_path)
    selector = run(tmp_path).dependency_selectors[0]
    values = {**selector.model_dump(), **updates}
    with pytest.raises(ValueError):
        DependencySelector.model_validate(values)
