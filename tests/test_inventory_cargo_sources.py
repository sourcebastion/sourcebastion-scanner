"""Cargo exact lock identities and unresolved static source declarations."""

import time
import pytest
from sourcebastion.inventory import cargo_sources
from sourcebastion.inventory.inputs import InputRefusal

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
checksum="{'a'*64}"
"""


def read(content=LOCK, fmt="cargo-lock", **kwargs):
    return cargo_sources.parse(content.encode(), fmt, deadline=time.monotonic() + 5, check=lambda: None, **kwargs)


@pytest.mark.parametrize("version", [3, 4])
def test_lock_version_exact_identity_and_artifact_checksum(version):
    result = read(LOCK.replace("version=4", f"version={version}", 1))
    assert result.disposition == "parsed" and len(result.packages) == 2
    parent, child = result.packages
    assert parent.admitted and child.admitted
    (ref,) = parent.dependencies
    assert (ref.name, ref.version, ref.source) == ("beta", "2.0.0", REGISTRY)
    assert child.hashes == (("sha256", "a" * 64),)


@pytest.mark.parametrize(
    "selector,version,source",
    [
        ("beta", None, None),
        ("beta 2.0.0", "2.0.0", None),
        (f"beta 2.0.0 ({REGISTRY})", "2.0.0", REGISTRY),
    ],
)
def test_source_selector_qualifiers_preserved(selector, version, source):
    result = read(LOCK.replace(f"beta 2.0.0 ({REGISTRY})", selector, 1))
    (ref,) = result.packages[0].dependencies
    assert (ref.name, ref.version, ref.source) == ("beta", version, source)


@pytest.mark.parametrize("value", ["", "git+https://example.invalid/repo#" + "a" * 40, "path+file:///secret/path"])
def test_nonregistry_package_retains_blocker_but_no_matching_identity(value):
    text = (
        LOCK.replace(f'source="{REGISTRY}"', f'source="{value}"', 1)
        if value
        else LOCK.replace(f'source="{REGISTRY}"\n', "", 1)
    )
    result = read(text)
    assert result.disposition == "unsupported" and len(result.packages) == 2
    assert not result.packages[0].admitted and result.packages[1].admitted


@pytest.mark.parametrize(
    "broken",
    [
        LOCK.replace("version=4", "version=5", 1),
        LOCK.replace('name="alpha"', "name=[]"),
        LOCK.replace('version="1.2.3"', 'version="1"'),
        LOCK.replace("dependencies=[", "dependencies={"),
        LOCK.replace("a" * 64, "z" * 64),
    ],
)
def test_malformed_lock_has_typed_disposition(broken):
    result = read(broken)
    assert result.disposition in {"unsupported", "failed"} and not result.packages


def test_manifest_versions_never_promote_a_floor_version():
    result = read('[package]\nname="demo"\nversion="0.1.0"\n[dependencies]\nalpha="1.2.3"\n', fmt="cargo-manifest")
    assert result.application == ("demo", "0.1.0") and not result.packages
    assert result.declarations[0].expression == "1.2.3"
    assert result.disposition == "unsupported" and result.reason == "unresolved-cargo-manifest-requirement"


def test_optional_build_dev_and_target_declarations_remain_distinct():
    text = """[package]
name="demo"
version="0.1.0"
[dependencies]
alpha={version="^1",optional=true,features=["derive"]}
[dev-dependencies]
alpha="2"
[target.'cfg(target_os = "linux")'.build-dependencies]
renamed={package="actual",version="3"}
"""
    result = read(text, fmt="cargo-manifest")
    assert len(result.declarations) == 3
    runtime, dev, build = result.declarations
    assert runtime.scopes == ("runtime", "optional") and runtime.features == ("derive",)
    assert dev.scopes == ("dev",) and dev.expression == "2"
    assert build.name == "actual" and build.scopes == ("build",) and build.condition == 'cfg(target_os = "linux")'


def test_workspace_inheritance_not_joined_to_arbitrary_manifest():
    result = read(
        '[package]\nname="demo"\nversion.workspace=true\n[dependencies]\nalpha.workspace=true\n', fmt="cargo-manifest"
    )
    assert result.application == ("demo", None)
    assert result.declarations[0].expression is None and result.disposition == "unsupported"


def test_private_range_is_redacted_without_a_grammar_claim():
    result = read(
        '[package]\nname="demo"\n[dependencies]\nalpha="https://user:secret@example.invalid/repo"\n',
        fmt="cargo-manifest",
    )
    assert result.declarations[0].expression is None
    assert "secret" not in repr(result)


def test_deep_array_refused_before_stdlib_decode(monkeypatch):
    def decoded(*args, **kwargs):
        raise AssertionError("decoded after preflight refusal")

    monkeypatch.setattr(cargo_sources.tomllib, "loads", decoded)
    result = read("version=4\nignored=" + "[" * 33 + "0" + "]" * 33)
    assert result.disposition == "bounded-omission" and result.reason == "cargo-toml-depth-budget-exceeded"


def test_shared_caller_budget_propagates():
    def stop():
        raise InputRefusal("composition-check-budget-exceeded")

    with pytest.raises(InputRefusal, match="composition-check-budget-exceeded"):
        cargo_sources.parse(LOCK.encode(), "cargo-lock", deadline=time.monotonic() + 5, check=stop)


def test_record_budget_counts_dependency_selectors():
    result = read(max_records=2)
    assert result.disposition == "bounded-omission" and not result.packages


@pytest.mark.parametrize("ending", ['"' * 4, '"' * 5, "'" * 4, "'" * 5])
def test_multiline_closing_literal_quotes_cannot_hide_array_depth(monkeypatch, ending):
    def decoded(*args, **kwargs):
        raise AssertionError("decoder reached after excessive array depth")

    monkeypatch.setattr(cargo_sources.tomllib, "loads", decoded)
    content = "version=4\nignored=" + ending[0] * 3 + "safe" + ending + "\narray=" + "[" * 33 + "0" + "]" * 33
    result = read(content)
    assert result.reason == "cargo-toml-depth-budget-exceeded"


@pytest.mark.parametrize("edition", [None, "2015", "2018", "2021"])
@pytest.mark.parametrize("field,scope", [("dev_dependencies", "dev"), ("build_dependencies", "build")])
@pytest.mark.parametrize("target", [False, True])
def test_legacy_tables_preserve_declarations_and_scopes(edition, field, scope, target):
    content = '[package]\nname="demo"\n'
    if edition is not None:
        content += f'edition="{edition}"\n'
    table = f"target.'cfg(unix)'.{field}" if target else field
    result = read(content + f'[{table}]\nalpha="1.2.3"\n', fmt="cargo-manifest")
    assert result.disposition == "unsupported"
    assert len(result.declarations) == 1
    declaration = result.declarations[0]
    assert declaration.name == "alpha" and declaration.scopes == (scope,)
    assert declaration.expression == "1.2.3" and declaration.locator.endswith(field + ".alpha")
    assert declaration.condition == ("cfg(unix)" if target else None)


@pytest.mark.parametrize("edition", ['"2024"', "{workspace=true}", '"2099"'])
def test_legacy_tables_with_new_or_unresolved_edition_cannot_be_complete(edition):
    result = read(f'[package]\nname="demo"\nedition={edition}\n[dev_dependencies]\nalpha="1"\n', fmt="cargo-manifest")
    assert result.disposition == "unsupported"
    if edition != '"2024"':
        assert len(result.declarations) == 1


def test_hyphenated_table_precedence_does_not_erase_ignored_alias_uncertainty():
    result = read(
        '[package]\nname="demo"\nedition="2021"\n[dev_dependencies]\nignored="1"\n[dev-dependencies]\nselected="2"\n',
        fmt="cargo-manifest",
    )
    assert result.disposition == "unsupported" and [d.name for d in result.declarations] == ["selected"]


def test_duplicate_unreferenced_exact_lock_identity_is_partial():
    entry = f'[[package]]\nname="alpha"\nversion="1.2.3"\nsource="{REGISTRY}"\n'
    result = read("version=4\n" + entry + entry)
    assert result.disposition == "unsupported" and result.reason == "duplicate-cargo-lock-identity"
    assert len(result.packages) == 2


def test_same_name_version_at_distinct_registry_sources_is_not_duplicate():
    entry = f'[[package]]\nname="alpha"\nversion="1.2.3"\nsource="{REGISTRY}"\n'
    result = read("version=4\n" + entry + entry.replace(REGISTRY, "registry+https://example.invalid/index"))
    assert result.disposition == "parsed" and len(result.packages) == 2
