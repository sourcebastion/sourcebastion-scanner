"""Check the M048 acceptance corpus against its recorded expectations.

Run inside the scanner image, which has the Linux npm selector runtime:

    docker run --rm --entrypoint /opt/venv/bin/python \
      -v "$PWD/evaluation/m048:/m048:ro" -v "$PWD/scripts:/scripts:ro" \
      <image> -I /scripts/verify-m048-license-acceptance.py /m048

It composes the corpus offline, evaluates its policy and prints one JSON
report. Exit status is 0 only when every package and the summary match.
"""

import json
import sys
from pathlib import Path

from sourcebastion.config import Config
from sourcebastion.license_checker import check_licenses, compose_licensed_inventory


def main(root):
    root = Path(root)
    expected = json.loads((root / "license-expectations.json").read_text())
    corpus = root / expected["corpus"]
    inventory = compose_licensed_inventory(str(corpus))
    policy = Config.from_file(str(root / expected["policy"])).license_policy.to_policy()
    result = check_licenses(str(corpus), policy, inventory=inventory)
    summary = {key: result["summary"][key] for key in expected["summary"]}
    packages = {row["name"]: row["result"] for row in result["packages"]}
    findings = {row["package"]: row["rule_id"] for row in result["findings"]}
    mismatches = []
    if summary != expected["summary"]:
        mismatches.append({"summary": summary})
    if result["summary"]["license_list_version"] != expected["license_list_version"]:
        mismatches.append({"license_list_version": result["summary"]["license_list_version"]})
    for name, row in expected["packages"].items():
        if packages.get(name) != row["result"] or findings.get(name) != row.get("rule_id"):
            mismatches.append({name: {"result": packages.get(name), "rule_id": findings.get(name)}})
    for name in set(packages) - set(expected["packages"]):
        mismatches.append({name: "unexpected package"})
    report = {
        "schema_version": "sourcebastion.m048-license-acceptance-run/1",
        "inventory_schema": inventory.schema_version,
        "inventory_state": inventory.stages.inventory,
        "refusal_codes": list(inventory.coverage.refusal_codes),
        "summary": result["summary"],
        "packages": packages,
        "mismatches": mismatches,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not mismatches else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
