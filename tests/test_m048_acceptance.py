"""M048 S07: the acceptance corpus evaluates exactly as recorded."""

import json
from pathlib import Path

import pytest

from sourcebastion.config import Config
from sourcebastion.license_checker import check_licenses, compose_licensed_inventory

ROOT = Path(__file__).resolve().parents[1] / "evaluation/m048"
EXPECTED = json.loads((ROOT / "license-expectations.json").read_text())


@pytest.fixture(scope="module")
def result():
    corpus = ROOT / EXPECTED["corpus"]
    inventory = compose_licensed_inventory(str(corpus))
    if "npm-selector-runtime-unavailable" in inventory.coverage.refusal_codes:
        pytest.skip("npm selector runtime needs Linux /proc; run in CI or the scanner image")
    policy = Config.from_file(str(ROOT / EXPECTED["policy"])).license_policy
    return check_licenses(str(corpus), policy.to_policy(), inventory=inventory)


def test_summary(result):
    summary = {key: result["summary"][key] for key in EXPECTED["summary"]}
    assert summary == EXPECTED["summary"]
    assert result["summary"]["license_list_version"] == EXPECTED["license_list_version"]


def test_every_package(result):
    packages = {row["name"]: row["result"] for row in result["packages"]}
    assert packages == {name: row["result"] for name, row in EXPECTED["packages"].items()}
    findings = {row["package"]: row["rule_id"] for row in result["findings"]}
    assert findings == {
        name: row["rule_id"] for name, row in EXPECTED["packages"].items() if "rule_id" in row
    }
