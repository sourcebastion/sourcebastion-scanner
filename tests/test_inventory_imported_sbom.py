"""Bounded admission of an imported build SBOM.

The gate decides whether a document may be admitted and records what was. It
produces no occurrences, so none of these tests assert one: an import that
could quietly become inventory is the failure the slice forbids.
"""

import hashlib
import json

import pytest

from sourcebastion.inventory.contract import InventoryLimits
from sourcebastion.inventory.imported_sbom import (
    FORMAT,
    MAX_IMPORT_BYTES,
    SPECIFICATIONS,
    ImportedBom,
    admit,
)
from sourcebastion.inventory.inputs import InputRefusal

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
