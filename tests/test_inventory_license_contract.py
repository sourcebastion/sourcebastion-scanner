"""M048 S01: inventory/2 license evidence, and /1 left exactly as it was."""

import hashlib
import json

import pytest
from pydantic import ValidationError

from sourcebastion.inventory.canonical_reader import CanonicalReaderError, read_canonical
from sourcebastion.inventory.contract import (
    INVENTORY_V1,
    INVENTORY_V2,
    LicenseGap,
    LicenseObservation,
    ProviderReference,
    canonical_bytes,
    identifier,
)
from sourcebastion.license_expression import SPDX_LICENSE_LIST_VERSION

from tests.test_inventory_contract import SHA, inventory, locator, occurrence


def observation(occ, raw="MIT", *, expression="MIT", parse="canonical", evidence="package-metadata", **changes):
    values = dict(
        id=identifier("license", [occ.id, raw, evidence]),
        occurrence_id=occ.id,
        source=locator(),
        evidence=evidence,
        value_raw=raw,
        expression=expression,
        parse=parse,
    )
    values.update(changes)
    return LicenseObservation(**values)


def gap(occ, reason="ecosystem-lock-carries-no-license"):
    return LicenseGap(id=identifier("license-gap", [occ.id]), occurrence_id=occ.id, reason=reason)


def v2(occurrences, licenses=(), gaps=(), **changes):
    values = dict(
        schema_version=INVENTORY_V2,
        occurrences=tuple(occurrences),
        licenses=tuple(licenses),
        license_gaps=tuple(gaps),
        license_list_version=SPDX_LICENSE_LIST_VERSION,
    )
    values.update(changes)
    return inventory(**values)


def read(raw):
    return read_canonical(raw, expected_sha256=hashlib.sha256(raw).hexdigest(), check=lambda: None)


class TestObservation:
    @pytest.mark.parametrize(
        "raw,expression,parse",
        [
            ("mit or apache-2.0", "MIT OR Apache-2.0", "canonical"),
            ("GPL-2.0+", "GPL-2.0+", "deprecated"),
            ("LicenseRef-Internal", "LicenseRef-Internal", "licenseref"),
            ("NOASSERTION", None, "unparsed"),
            ("see LICENSE", None, "unparsed"),
        ],
    )
    def test_parse_must_agree_with_the_pinned_list(self, raw, expression, parse):
        occ = occurrence()
        assert observation(occ, raw, expression=expression, parse=parse).parse == parse

    @pytest.mark.parametrize(
        "raw,expression,parse",
        [
            ("Foo", "Foo", "canonical"),  # free text asserted as an identifier
            ("MIT", None, "unparsed"),  # parseable value hidden as unparsed
            ("mit", "mit", "canonical"),  # noncanonical expression
            ("GPL-2.0+", "GPL-2.0+", "canonical"),  # deprecation hidden
        ],
    )
    def test_contradictory_parse_is_refused(self, raw, expression, parse):
        with pytest.raises(ValidationError, match="contradictory-license-parse"):
            observation(occurrence(), raw, expression=expression, parse=parse)

    def test_raw_value_is_bounded_and_control_free(self):
        with pytest.raises(ValidationError):
            observation(occurrence(), "MIT\x00", expression="MIT")
        with pytest.raises(ValidationError):
            observation(occurrence(), "x" * 16385, expression=None, parse="unparsed")

    def test_unknown_fields_and_evidence_kinds_are_refused(self):
        with pytest.raises(ValidationError):
            observation(occurrence(), evidence="registry-lookup")
        with pytest.raises(ValidationError):
            observation(occurrence(), inferred=True)


class TestInventoryV2:
    def test_round_trip_through_the_canonical_reader(self):
        occ = occurrence()
        record = v2([occ], [observation(occ), observation(occ, "NOASSERTION", expression=None, parse="unparsed")])
        raw = canonical_bytes(record)
        assert read(raw) == record
        data = json.loads(raw)
        assert data["schema_version"] == INVENTORY_V2
        assert data["license_list_version"] == SPDX_LICENSE_LIST_VERSION
        assert [row["id"] for row in data["licenses"]] == sorted(row["id"] for row in data["licenses"])

    def test_gap_and_noassertion_stay_distinct(self):
        a, b = occurrence(name="pip"), occurrence(name="six", purl="pkg:pypi/six@1.0.0", selected_version="1.0.0")
        record = v2([a, b], [observation(a, "NOASSERTION", expression=None, parse="unparsed")], [gap(b)])
        data = json.loads(canonical_bytes(record))
        assert data["licenses"][0]["value_raw"] == "NOASSERTION"
        assert data["license_gaps"][0]["reason"] == "ecosystem-lock-carries-no-license"

    def test_conflicting_observations_are_all_retained(self):
        occ = occurrence()
        record = v2(
            [occ],
            [
                observation(occ, "MIT", evidence="package-metadata"),
                observation(occ, "GPL-3.0-only", expression="GPL-3.0-only", evidence="declared-manifest"),
            ],
        )
        assert len(record.licenses) == 2

    def test_every_occurrence_must_be_assessed(self):
        with pytest.raises(ValidationError, match="unassessed-occurrence-license"):
            v2([occurrence()])

    def test_gap_cannot_coexist_with_observation(self):
        occ = occurrence()
        with pytest.raises(ValidationError, match="contradictory-license-gap"):
            v2([occ], [observation(occ)], [gap(occ)])

    def test_observation_must_bind_an_occurrence(self):
        occ = occurrence()
        stranger = occurrence(name="six", purl="pkg:pypi/six@1.0.0", selected_version="1.0.0")
        with pytest.raises(ValidationError, match="unbound-license-occurrence"):
            v2([occ], [observation(occ), observation(stranger)])

    def test_observation_must_bind_read_coverage(self):
        occ = occurrence()
        unread = observation(occ, source=locator("pyproject.toml"))
        with pytest.raises(ValidationError, match="unbound-source-coverage"):
            v2([occ], [unread])

    def test_imported_claims_belong_only_to_imported_occurrences(self):
        occ = occurrence()
        with pytest.raises(ValidationError, match="imported-license-requires-imported-occurrence"):
            v2([occ], [observation(occ, evidence="imported-claim")])

    def test_provider_license_requires_a_provider_reference(self):
        occ = occurrence()
        with pytest.raises(ValidationError, match="provider-license-requires-provider-reference"):
            v2([occ], [observation(occ, evidence="provider")])
        reference = ProviderReference(provider_output_sha256=SHA, raw_record_sha256=SHA)
        referenced = occurrence().model_copy(update={"provider_references": (reference,)})
        assert v2([referenced], [observation(referenced, evidence="provider")])

    def test_license_list_version_is_pinned(self):
        occ = occurrence()
        for version in (None, "3.26.0"):
            with pytest.raises(ValidationError, match="license-list-version-mismatch"):
                v2([occ], [observation(occ)], license_list_version=version)

    def test_mistyped_record_ids_are_refused(self):
        occ = occurrence()
        with pytest.raises(ValidationError, match="duplicate-or-mistyped-record-id"):
            v2([occ], [observation(occ, id=identifier("license-gap", ["x"]))])


class TestInventoryV1:
    def test_v1_bytes_carry_no_license_fields(self):
        raw = canonical_bytes(inventory(occurrences=(occurrence(),)))
        data = json.loads(raw)
        assert data["schema_version"] == INVENTORY_V1
        assert not {"licenses", "license_gaps", "license_list_version"} & set(data)
        assert read(raw).schema_version == INVENTORY_V1

    def test_v1_cannot_carry_license_evidence(self):
        occ = occurrence()
        for changes in (
            dict(licenses=(observation(occ),)),
            dict(license_gaps=(gap(occ),)),
            dict(license_list_version=SPDX_LICENSE_LIST_VERSION),
        ):
            with pytest.raises(ValidationError, match="license-evidence-requires-inventory-v2"):
                inventory(occurrences=(occ,), **changes)

    def test_v1_bytes_with_injected_license_fields_are_refused(self):
        data = json.loads(canonical_bytes(inventory(occurrences=(occurrence(),))))
        data["licenses"] = []
        raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        with pytest.raises(CanonicalReaderError, match="canonical_inventory_noncanonical"):
            read(raw)

    def test_license_list_version_is_part_of_v2_identity(self):
        occ = occurrence()
        record = v2([occ], gaps=[gap(occ)])
        assert json.loads(canonical_bytes(record))["license_list_version"] == SPDX_LICENSE_LIST_VERSION
        # Another list version cannot be re-emitted under this one's bytes.
        with pytest.raises(ValueError, match="license-list-version-mismatch"):
            canonical_bytes(record.model_copy(update={"license_list_version": "9.9.9"}))
