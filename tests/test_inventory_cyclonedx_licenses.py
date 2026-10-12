"""M048 S05: license evidence in exported CycloneDX and imported claims."""

import json

import pytest

from sourcebastion.inventory.contract import INVENTORY_V1, InventoryLimits
from sourcebastion.inventory.imported_sbom import project
from tests.test_inventory_cyclonedx import emit, props, standard  # noqa: F401  (fixture)
from tests.test_inventory_license_contract import gap, observation, v2
from tests.test_inventory_contract import inventory, occurrence


def components(artifact):
    return {row["name"]: row for row in json.loads(artifact.content)["components"]}


def losses(component):
    return dict(props(component["properties"]))["projection-losses"]


def three():
    single = occurrence(name="six", purl="pkg:pypi/six@1.0.0", selected_version="1.0.0")
    unparsed = occurrence(name="attrs", purl="pkg:pypi/attrs@1.0.0", selected_version="1.0.0")
    silent = occurrence(name="idna", purl="pkg:pypi/idna@1.0.0", selected_version="1.0.0")
    return single, unparsed, silent


def test_single_expression_is_declared_and_schema_valid(standard):
    single, unparsed, silent = three()
    record = v2(
        [single, unparsed, silent],
        [
            observation(single, "mit or apache-2.0", expression="MIT OR Apache-2.0"),
            observation(unparsed, "see LICENSE", expression=None, parse="unparsed"),
        ],
        [gap(silent)],
    )
    artifact = emit(record)
    standard.validate(json.loads(artifact.content))
    rows = components(artifact)
    assert rows["six"]["licenses"] == [{"expression": "MIT OR Apache-2.0", "acknowledgement": "declared"}]
    assert "license-evidence-not-representable" not in losses(rows["six"])
    for name in ("attrs", "idna"):
        assert "licenses" not in rows[name]
        assert "license-evidence-not-representable" in losses(rows[name])
    assert dict(props(rows["attrs"]["properties"]))["license-observation"]["value_raw"] == "see LICENSE"
    assert dict(props(rows["idna"]["properties"]))["license-gap"]["reason"] == "ecosystem-lock-carries-no-license"


def test_identifier_missing_from_the_cyclonedx_enum_still_validates(standard):
    # 3D-Slicer-1.0 is in SPDX 3.27.0 but not in CycloneDX 1.6's enumeration.
    single, _, _ = three()
    record = v2([single], [observation(single, "3D-Slicer-1.0", expression="3D-Slicer-1.0")])
    artifact = emit(record)
    standard.validate(json.loads(artifact.content))
    assert components(artifact)["six"]["licenses"] == [{"expression": "3D-Slicer-1.0", "acknowledgement": "declared"}]


def test_conflicting_claims_are_not_flattened(standard):
    single, _, _ = three()
    record = v2(
        [single],
        [
            observation(single, "MIT", evidence="package-metadata"),
            observation(single, "GPL-3.0-only", expression="GPL-3.0-only", evidence="declared-manifest"),
        ],
    )
    artifact = emit(record)
    standard.validate(json.loads(artifact.content))
    row = components(artifact)["six"]
    assert "licenses" not in row
    assert "license-evidence-not-representable" in losses(row)
    assert sum(name == "license-observation" for name, _ in props(row["properties"])) == 2


def test_identity_is_byte_reproducible_with_license_data():
    single, unparsed, silent = three()
    record = v2([single, unparsed, silent], [observation(single)], [gap(unparsed), gap(silent)])
    first, second = emit(record), emit(record)
    assert first.content == second.content
    assert first.identity_sha256 == second.identity_sha256
    assert "timestamp" not in json.loads(first.content)["metadata"]


def test_v1_export_is_unchanged():
    record = inventory(occurrences=(occurrence(),))
    assert record.schema_version == INVENTORY_V1
    artifact = emit(record)
    row = json.loads(artifact.content)["components"][0]
    assert "licenses" not in row
    assert losses(row) == ["cyclonedx-default-required-scope-unassessed"]
    assert "license-list-version" not in dict(props(json.loads(artifact.content)["metadata"]["properties"]))


class TestImportedClaims:
    def test_round_trip_reads_back_as_imported_claims_only(self):
        single, _, _ = three()
        exported = emit(v2([single], [observation(single, "MIT OR Apache-2.0", expression="MIT OR Apache-2.0")]))
        projection = project(exported.content, limits=InventoryLimits(), check=lambda: None)
        (claim,) = projection.licenses
        (imported,) = projection.occurrences
        assert imported.evidence_kind == "imported"
        assert (claim.occurrence_id, claim.evidence, claim.expression) == (
            imported.id,
            "imported-claim",
            "MIT OR Apache-2.0",
        )
        assert claim.source.locator == "imported-sbom:/components/0/licenses/0"

    @pytest.mark.parametrize(
        "entry,expected",
        [
            ({"license": {"id": "Apache-2.0"}}, ("Apache-2.0", "canonical")),
            ({"license": {"name": "Acme Commercial"}}, ("Acme Commercial", "unparsed")),
            ({"license": {"url": "https://example.com/l"}}, ('{"url":"https://example.com/l"}', "unparsed")),
            ("MIT", ("MIT", "canonical")),
        ],
    )
    def test_entry_shapes(self, entry, expected):
        document = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {"type": "library", "name": "six", "version": "1.0.0", "purl": "pkg:pypi/six@1.0.0", "licenses": [entry]}
            ],
        }
        projection = project(json.dumps(document).encode(), limits=InventoryLimits(), check=lambda: None)
        (claim,) = projection.licenses
        assert (claim.value_raw, claim.parse) == expected

    def test_claims_on_skipped_components_are_dropped_with_them(self):
        document = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{"type": "library", "name": "six", "licenses": [{"expression": "MIT"}]}],
        }
        projection = project(json.dumps(document).encode(), limits=InventoryLimits(), check=lambda: None)
        assert projection.skipped == 1 and projection.licenses == ()
