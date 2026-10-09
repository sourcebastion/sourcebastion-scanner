"""Bounded admission and projection of an imported build SBOM.

`admit` is the gate alone: it decides whether a document may be admitted and
records what was, and produces no occurrences. `project` is the import proper,
and every occurrence it builds carries `evidence_kind="imported"`. An import
that could pass for something discovery found in the source is the failure
these tests forbid, so projection is asserted to stay separate rather than to
stay absent.
"""

import hashlib
import json

import pytest

from sourcebastion.inventory.compose_source import compose_source
from sourcebastion.inventory.contract import InventoryLimits, Producer
from sourcebastion.inventory.imported_sbom import (
    FORMAT,
    MAX_IMPORT_BYTES,
    SPECIFICATIONS,
    ImportedBom,
    admit,
    project,
)
from sourcebastion.inventory.inputs import InputRefusal, Source
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256

LIMITS = InventoryLimits()


def document(**changes):
    value = {
        "bomFormat": FORMAT,
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {"type": "library", "name": "pip", "version": "26.0.1",
             "purl": "pkg:pypi/pip@26.0.1"}
        ],
    }
    value.update(changes)
    return json.dumps(value).encode()


def test_a_controller_supplied_document_is_identified_by_digest_alone():
    raw = document()

    admitted = admit(raw, limits=LIMITS, check=lambda: None)

    assert admitted.binding == "controller" and admitted.path is None
    assert admitted.sha256 == hashlib.sha256(raw).hexdigest()
    assert admitted.specification == "1.6" and admitted.components == 1


def test_a_source_bound_document_keeps_its_confined_path():
    admitted = admit(
        document(), limits=LIMITS, check=lambda: None, path="build/sbom.cdx.json"
    )

    assert admitted.binding == "source"
    assert admitted.path == "build/sbom.cdx.json"


@pytest.mark.parametrize(
    "path", ["/etc/passwd", "../outside.json", "a\\b.json", "", "x\x00y"]
)
def test_an_unconfined_path_is_refused(path):
    """The same rule a manifest gets, not a second path implementation."""
    with pytest.raises(InputRefusal, match="unsafe-input-path|invalid-path-encoding"):
        admit(document(), limits=LIMITS, check=lambda: None, path=path)


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"bomFormat": "SPDX"}, "unsupported-imported-sbom-format"),
        ({"specVersion": "1.5"}, "unsupported-imported-sbom-specification"),
        ({"specVersion": 1.6}, "unsupported-imported-sbom-specification"),
        ({"components": {"name": "pip"}}, "invalid-imported-sbom-components"),
    ],
)
def test_a_document_outside_the_allowlist_is_refused(changes, reason):
    with pytest.raises(ValueError, match=reason):
        admit(document(**changes), limits=LIMITS, check=lambda: None)


def test_a_neighbouring_specification_is_not_coerced():
    """1.5 is not 1.6 with fields missing, and guessing is how an import
    starts asserting what its bytes do not say."""
    assert "1.5" not in SPECIFICATIONS

    with pytest.raises(ValueError, match="specification"):
        admit(document(specVersion="1.5"), limits=LIMITS, check=lambda: None)


def test_duplicate_keys_and_nonfinite_numbers_are_refused():
    with pytest.raises(ValueError, match="invalid-imported-sbom"):
        admit(b'{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}',
              limits=LIMITS, check=lambda: None)
    with pytest.raises(ValueError, match="invalid-imported-sbom"):
        admit(b'{"bomFormat":"CycloneDX","specVersion":"1.6","x":NaN}',
              limits=LIMITS, check=lambda: None)


def test_an_oversized_document_is_refused_atomically():
    """Refused whole: a truncated SBOM admitted as a complete one would
    understate what the build contained."""
    with pytest.raises(InputRefusal, match="byte-budget"):
        admit(b" " * (MAX_IMPORT_BYTES + 1), limits=LIMITS, check=lambda: None)


def test_deep_nesting_is_refused_before_parsing():
    raw = b"[" * 200 + b"]" * 200
    with pytest.raises(InputRefusal, match="depth-budget"):
        admit(raw, limits=LIMITS, check=lambda: None)


def test_admission_charges_the_callers_ledger():
    charges = []
    admit(document(), limits=LIMITS, check=lambda: charges.append(1))

    assert charges, "admission must charge the shared ledger like every stage"


def test_a_binding_cannot_disagree_with_its_path():
    with pytest.raises(ValueError, match="invalid-import-binding"):
        ImportedBom(sha256="a" * 64, specification="1.6", components=0,
                    binding="source", path=None)
    with pytest.raises(ValueError, match="invalid-import-binding"):
        ImportedBom(sha256="a" * 64, specification="1.6", components=0,
                    binding="controller", path="build/sbom.json")


def test_admission_yields_facts_and_never_an_inventory():
    """The gate's whole point: nothing here can become an occurrence."""
    admitted = admit(document(), limits=LIMITS, check=lambda: None)

    assert not hasattr(admitted, "occurrences")
    assert set(vars(admitted)) == {
        "sha256", "specification", "components", "binding", "path",
        "schema_version",
    }


def test_the_gate_alone_still_yields_no_occurrences():
    """`admit` remains the gate: a caller that wants rows must ask for them."""
    admitted = admit(document(), limits=LIMITS, check=lambda: None)

    assert not hasattr(admitted, "occurrences")


def test_every_projected_occurrence_is_marked_imported():
    projection = project(
        document(
            components=[
                {"type": "library", "name": "pip", "version": "26.0.1",
                 "purl": "pkg:pypi/pip@26.0.1"},
                {"type": "library", "name": "left-pad", "version": "1.3.0",
                 "purl": "pkg:npm/left-pad@1.3.0"},
            ]
        ),
        limits=LIMITS,
        check=lambda: None,
        path="build/sbom.cdx.json",
    )

    assert [row.evidence_kind for row in projection.occurrences] == [
        "imported",
        "imported",
    ]
    assert [row.purl for row in projection.occurrences] == [
        "pkg:pypi/pip@26.0.1",
        "pkg:npm/left-pad@1.3.0",
    ]
    assert projection.skipped == 0
    assert projection.admitted.binding == "source"


def test_imported_occurrences_name_the_import_and_not_a_parsed_input():
    """A reader must be able to tell the admitted document from the tree."""
    projection = project(
        document(), limits=LIMITS, check=lambda: None, path="build/sbom.cdx.json"
    )

    assert projection.scope.kind == "imported-sbom-input"
    assert projection.scope.source.locator == "imported-sbom"
    assert projection.scope.source.path == "build/sbom.cdx.json"
    assert {row.analysis_scope_id for row in projection.occurrences} == {
        projection.scope.id
    }


def test_a_controller_supplied_projection_has_no_source_path_to_claim():
    projection = project(document(), limits=LIMITS, check=lambda: None)

    assert projection.admitted.binding == "controller"
    assert projection.admitted.path is None
    assert projection.scope.source.path == "(controller-supplied)"


def test_an_imported_occurrence_never_collides_with_a_discovered_one(tmp_path):
    """Equal purls are not established to be the same thing: the built
    artifact and the declared dependency stay two occurrences."""
    (tmp_path / "uv.lock").write_text(
        'version=1\nrevision=3\nrequires-python=">=3.12"\n'
        '[[package]]\nname="foo"\nversion="1"\n'
        'source={registry="https://pypi.org/simple"}\n'
        'wheels=[{url="https://packages.invalid/foo-1-py3-none-any.whl",'
        'hash="sha256:' + "a" * 64 + '"}]\n'
    )
    config = DiscoveryConfig()
    with Source(tmp_path) as source:
        composed = compose_source(
            source,
            source_sha256="a" * 64,
            producer=Producer(
                name="test",
                version="1",
                code_sha256="a" * 64,
                registry_sha256=REGISTRY_SHA256,
                config_sha256=config.sha256,
            ),
            config=config,
        )
    (discovered,) = composed.occurrences
    assert discovered.purl == "pkg:pypi/foo@1" and discovered.evidence_kind == "locked"

    projection = project(
        document(
            components=[
                {"type": "library", "name": "foo", "version": "1",
                 "purl": "pkg:pypi/foo@1"}
            ]
        ),
        limits=LIMITS,
        check=lambda: None,
        path="build/sbom.cdx.json",
    )
    (imported,) = projection.occurrences

    assert imported.purl == discovered.purl
    assert imported.id != discovered.id
    assert imported.evidence_kind == "imported"
    assert imported.analysis_scope_id != composed.analysis_scopes[0].id


@pytest.mark.parametrize(
    "component",
    [
        {"type": "library", "name": "x", "version": "1", "purl": "pkg:unknown/x@1"},
        {"type": "library", "name": "x", "version": "1"},
        {"type": "library", "name": "x", "purl": "pkg:pypi/x"},
        {"type": "library", "version": "1", "purl": "pkg:pypi/x@1"},
        {"type": "library", "name": 7, "version": "1", "purl": "pkg:pypi/x@1"},
        "not-a-component",
    ],
)
def test_a_component_the_contract_cannot_state_is_skipped_and_counted(component):
    """Skipped rather than guessed at, and visible rather than silently
    smaller: an import must not invent an ecosystem or a version."""
    projection = project(
        document(components=[component]), limits=LIMITS, check=lambda: None
    )

    assert projection.occurrences == ()
    assert projection.skipped == 1
    assert projection.admitted.components == 1


def test_a_skipped_component_does_not_stop_the_usable_ones():
    projection = project(
        document(
            components=[
                {"type": "library", "name": "x", "version": "1",
                 "purl": "pkg:unknown/x@1"},
                {"type": "library", "name": "pip", "version": "26.0.1",
                 "purl": "pkg:pypi/pip@26.0.1"},
            ]
        ),
        limits=LIMITS,
        check=lambda: None,
    )

    assert [row.name for row in projection.occurrences] == ["pip"]
    assert projection.skipped == 1


def test_a_component_contradicting_its_own_purl_is_skipped():
    """The purl names one version and the field another; neither is adopted."""
    projection = project(
        document(
            components=[
                {"type": "library", "name": "pip", "version": "26.0.1",
                 "purl": "pkg:pypi/pip@1.0.0"}
            ]
        ),
        limits=LIMITS,
        check=lambda: None,
    )

    assert projection.occurrences == ()
    assert projection.skipped == 1


def test_projection_charges_the_callers_ledger_per_component():
    charges = []
    project(
        document(
            components=[
                {"type": "library", "name": "pip", "version": "26.0.1",
                 "purl": "pkg:pypi/pip@26.0.1"},
                {"type": "library", "name": "left-pad", "version": "1.3.0",
                 "purl": "pkg:npm/left-pad@1.3.0"},
            ]
        ),
        limits=LIMITS,
        check=lambda: charges.append(1),
    )
    admissions = []
    admit(document(), limits=LIMITS, check=lambda: admissions.append(1))

    assert len(charges) > len(admissions), "per-component work must be charged"


def test_projection_is_refused_whole_on_an_inadmissible_document():
    """Projection runs the same gate: a refused document yields no rows."""
    with pytest.raises(ValueError, match="unsupported-imported-sbom-format"):
        project(document(bomFormat="SPDX"), limits=LIMITS, check=lambda: None)
    with pytest.raises(InputRefusal, match="unsafe-input-path"):
        project(document(), limits=LIMITS, check=lambda: None, path="../outside.json")


def test_a_source_digest_binds_the_projection_to_the_admitted_source():
    """When a caller read the bytes from an admitted source, the occurrences
    name that source's digest, not just the document's."""
    raw = document()
    projection = project(
        raw,
        limits=LIMITS,
        check=lambda: None,
        path="build/sbom.cdx.json",
        source_sha256="b" * 64,
    )

    assert projection.admitted.sha256 == hashlib.sha256(raw).hexdigest()
    assert projection.scope.source.source_sha256 == "b" * 64
    assert {row.source.source_sha256 for row in projection.occurrences} == {"b" * 64}


@pytest.mark.parametrize(
    "name,version,purl",
    [
        ("@scope/pkg", "1.0.0", "pkg:npm/%40scope/pkg@1.0.0"),
        ("@scope/pkg", "1.0.0", "pkg:npm/@scope/pkg@1.0.0"),
        ("pip", "26.0.1", "pkg:PyPI/pip@26.0.1"),
        ("pip", "26.0.1", "pkg:pypi/pip@26.0.1?file_name=pip.whl"),
        ("pip", "26.0.1", "pkg:pypi/pip@26.0.1#src"),
        ("org.slf4j/slf4j-api", "2.0.17", "pkg:maven/org.slf4j/slf4j-api@2.0.17?type=jar"),
    ],
)
def test_a_legally_written_purl_is_not_mistaken_for_a_contradiction(name, version, purl):
    """The agreement check compares identity, not spelling: encoding, type
    case, qualifiers and a subpath are all legal and must not cost a row."""
    projection = project(
        document(
            components=[{"type": "library", "name": name, "version": version,
                         "purl": purl}]
        ),
        limits=LIMITS,
        check=lambda: None,
    )

    assert projection.skipped == 0
    (row,) = projection.occurrences
    assert row.name == name and row.selected_version == version


@pytest.mark.parametrize(
    "purl",
    [
        "pkg:pypi/pip@1.0.0",
        "pkg:pypi/setuptools@26.0.1",
        "pkg:pypi/pip",
        "pkg:pypi/%70ip@26.0.2",
    ],
)
def test_a_purl_disagreeing_about_identity_costs_the_row(purl):
    """The ecosystem is read from the purl, so a differing type is not a
    disagreement -- a differing name or version is."""
    projection = project(
        document(
            components=[{"type": "library", "name": "pip", "version": "26.0.1",
                         "purl": purl}]
        ),
        limits=LIMITS,
        check=lambda: None,
    )

    assert projection.occurrences == ()
    assert projection.skipped == 1
