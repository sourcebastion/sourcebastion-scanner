"""M048 S06: license evidence carried by occurrence rows, never a verdict."""

import json

from tests.test_inventory_contract import inventory, occurrence
from tests.test_inventory_license_contract import gap, observation, v2
from tests.test_inventory_row_projection import project, table


def occurrences():
    names = ("stated", "conflicting", "unparsed", "unstated")
    return {name: occurrence(name=name, purl=f"pkg:pypi/{name}@1.0.0", selected_version="1.0.0") for name in names}


def projected():
    occ = occurrences()
    record = v2(
        list(occ.values()),
        [
            observation(occ["stated"], "mit or apache-2.0", expression="MIT OR Apache-2.0"),
            observation(occ["conflicting"], "MIT", evidence="package-metadata"),
            observation(occ["conflicting"], "GPL-3.0-only", expression="GPL-3.0-only", evidence="declared-manifest"),
            observation(occ["unparsed"], "MIT", evidence="package-metadata"),
            observation(occ["unparsed"], "see LICENSE", expression=None, parse="unparsed", evidence="declared-manifest"),
        ],
        [gap(occ["unstated"])],
    )
    return occ, project(record)


def test_occurrence_rows_carry_state_and_expression():
    occ, projection = projected()
    columns = {dict(row.columns)["name"]: dict(row.columns) for row in table(projection, "occurrence")}
    assert {name: (c["license_state"], c["license_expression"]) for name, c in columns.items()} == {
        "stated": ("stated", "MIT OR Apache-2.0"),
        "conflicting": ("conflicting", None),
        "unparsed": ("unparsed", None),
        "unstated": ("unstated", None),
    }


def test_facets_filter_by_state_and_stated_expression():
    occ, projection = projected()
    facets = {
        (dict(row.columns)["occurrence_id"], dict(row.columns)["facet"], dict(row.columns)["value"])
        for row in table(projection, "occurrence_facet")
        if dict(row.columns)["facet"].startswith("license")
    }
    assert facets == {
        (occ["stated"].id, "license_state", "stated"),
        (occ["stated"].id, "license", "MIT OR Apache-2.0"),
        (occ["conflicting"].id, "license_state", "conflicting"),
        (occ["unparsed"].id, "license_state", "unparsed"),
        (occ["unstated"].id, "license_state", "unstated"),
    }


def test_detail_keeps_every_observation_and_the_gap():
    occ, projection = projected()
    details = {json.loads(row.detail)["name"]: json.loads(row.detail) for row in table(projection, "occurrence")}
    assert len(details["conflicting"]["licenses"]) == 2
    assert details["unstated"]["license_gap"]["reason"] == "ecosystem-lock-carries-no-license"
    assert details["stated"]["license_gap"] is None


def test_license_records_do_not_bloat_snapshot_metadata():
    _, projection = projected()
    (snapshot,) = table(projection, "snapshot")
    metadata = json.loads(snapshot.detail)
    assert "licenses" not in metadata and "license_gaps" not in metadata
    assert metadata["license_list_version"] == "3.27.0"


def test_v1_projection_is_unchanged():
    projection = project(inventory(occurrences=(occurrence(),)))
    (row,) = table(projection, "occurrence")
    assert "license_state" not in dict(row.columns)
    assert "licenses" not in json.loads(row.detail)
    assert not [r for r in table(projection, "occurrence_facet") if dict(r.columns)["facet"].startswith("license")]
