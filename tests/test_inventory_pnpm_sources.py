"""Adversarial data-only lock parsing; source contexts never flatten."""

import time
import pytest
from sourcebastion.inventory.bounded_yaml import load_documents
from sourcebastion.inventory.inputs import InputRefusal
from sourcebastion.inventory.pnpm_sources import parse


def read(content, **kwargs):
    return parse(content, deadline=time.monotonic() + 10, check=lambda: None, **kwargs)


SIMPLE = b"""lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      alpha:
        specifier: ^1.0.0
        version: 1.2.3
packages:
  alpha@1.2.3:
    resolution:
      integrity: sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
snapshots:
  alpha@1.2.3: {}
"""


def test_registry_source_selection_and_lexical_version():
    result = read(SIMPLE)
    assert result.disposition == "parsed"
    (doc,) = result.documents
    (package,) = doc.packages
    (importer,) = doc.importers
    (reference,) = importer.references
    assert (package.name, package.version, reference.selected, reference.declared_range) == (
        "alpha",
        "1.2.3",
        "1.2.3",
        "^1.0.0",
    )
    assert package.locator.startswith("documents[0]/snapshot:sha256:")
    assert importer.key == "."


def test_all_documents_preserve_independent_environment_and_project_contexts():
    result = read(SIMPLE.replace(b"dependencies:", b"configDependencies:", 1) + b"---\n" + SIMPLE)
    assert result.disposition == "parsed"
    first, second = result.documents
    assert (first.ordinal, second.ordinal) == (0, 1)
    assert first.packages[0].locator != second.packages[0].locator
    assert first.importers[0].references[0].scope == "build"
    assert second.importers[0].references[0].scope == "runtime"


def test_peer_snapshots_keep_distinct_exact_keys_and_context_hashes():
    source = SIMPLE
    source = source.rsplit(b"snapshots:", 1)[0] + b"""snapshots:
  alpha@1.2.3(beta@1.0.0): {}
  alpha@1.2.3(beta@2.0.0): {}
"""
    rows = read(source).documents[0].packages
    assert len(rows) == 2
    assert len({r.key for r in rows}) == len({r.peer_context_sha256 for r in rows}) == 2
    assert len({r.locator for r in rows}) == 2


@pytest.mark.parametrize(
    "malicious",
    [
        b"x: &ref [1]\ny: *ref",
        b"x: &ref [1]",
        b"x: !!python/object/apply:os.system [id]",
        b"x: !custom value",
        b"x: 1\nx: 2",
        b"x: {a: 1, a: 2}",
        b"<<: {a: 1}",
        b"? [one, two]\n: three",
        b"[one]",
        b"",
        b"x: \xff",
        b"x: [" + b"[" * 33 + b"]" * 33 + b"]",
        b"---\nx: 1\n" * 33,
    ],
)
def test_unsafe_yaml_refused_before_data_consumption(malicious):
    with pytest.raises(InputRefusal):
        load_documents(malicious, check=lambda: None)


@pytest.mark.parametrize("value", [b"[]", b"{}", b"truee", b"null", b"1"])
def test_invalid_boolean_never_raises_python_type_error(value):
    result = read(SIMPLE + b"settings:\n  autoInstallPeers: " + value + b"\n")
    assert result.disposition == "unsupported"
    assert result.reason == "invalid-pnpm-boolean"


def test_no_snapshot_does_not_invent_an_endpoint():
    result = read(SIMPLE.rsplit(b"snapshots:", 1)[0])
    (doc,) = result.documents
    assert doc.disposition == "unsupported"
    assert doc.reason == "missing-pnpm-snapshot"
    assert doc.packages[0].key == "package-only:alpha@1.2.3"


def test_unsupported_document_does_not_hide_second_document():
    result = read(b"lockfileVersion: '8.0'\n---\n" + SIMPLE)
    assert result.disposition == "unsupported"
    assert result.documents[0].disposition == "unsupported"
    assert result.documents[1].packages[0].name == "alpha"


def test_record_budget_is_shared_across_documents():
    result = read(SIMPLE + b"---\n" + SIMPLE, max_records=5)
    assert result.disposition == "bounded-omission"
    assert result.documents == ()


def test_outer_ledger_failure_propagates_instead_of_publishing_facts():
    def stop():
        raise InputRefusal("composition-check-budget-exceeded")

    with pytest.raises(InputRefusal, match="composition-check-budget-exceeded"):
        parse(SIMPLE, deadline=time.monotonic() + 10, check=stop)


def test_private_nonregistry_reference_is_not_a_public_locator():
    secret = b"https://user:secret@example.invalid/a.tgz"
    result = read(SIMPLE.replace(b"version: 1.2.3", b"version: " + secret))
    reference = result.documents[0].importers[0].references[0]
    assert reference.selected is None
    assert reference.reason == "unsupported-pnpm-reference"
    assert "secret" not in reference.locator


@pytest.mark.parametrize("resolution", [b"", b"    resolution: {}\n", b"    resolution: {revision: 1}\n"])
def test_incomplete_resolution_retains_observation_with_partial_coverage(resolution):
    content = b"lockfileVersion: '9.0'\npackages:\n  alpha@1.2.3:\n" + resolution + b"snapshots:\n  alpha@1.2.3: {}\n"
    # A missing mapping body is null YAML, so use an explicitly empty package.
    if not resolution:
        content = content.replace(b"  alpha@1.2.3:\nsnapshots:", b"  alpha@1.2.3: {}\nsnapshots:")
    result = read(content)
    assert result.disposition == "unsupported"
    assert result.reason == "incomplete-pnpm-package-resolution"
    assert result.documents[0].packages[0].version == "1.2.3"


def test_registry_and_tarball_resolution_alternatives_are_supported():
    content = SIMPLE.replace(
        b"integrity: sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        b"tarball: https://registry.npmjs.org/alpha/-/alpha-1.2.3.tgz",
    )
    result = read(content)
    assert result.disposition == "parsed"
    assert result.documents[0].packages[0].source_key is not None


@pytest.mark.parametrize("field", ["url", "peer-key"])
def test_unpaired_escaped_unicode_has_typed_refusal_before_hashing(field):
    content = (
        b'lockfileVersion: "9.0"\npackages:\n  alpha@1.0.0:\n    resolution:\n'
        b'      tarball: "https://example.invalid/\\uD800"\nsnapshots:\n  alpha@1.0.0: {}\n'
        if field == "url"
        else b'lockfileVersion: "9.0"\npackages:\n  alpha@1.0.0:\n    resolution: {integrity: sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}\nsnapshots:\n  "alpha@1.0.0(peer@\\uD800)": {}\n'
    )
    result = read(content)
    assert result.disposition == "failed" and result.reason == "invalid-yaml-unicode"
    assert not result.documents
