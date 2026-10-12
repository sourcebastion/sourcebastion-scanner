"""M048 S04: license policy over the canonical inventory, with no syft."""

import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from sourcebastion.cli import main
from sourcebastion.external_scanners import ScannerExecutionError
from sourcebastion.license_checker import check_licenses, compose_licensed_inventory, evaluate_inventory
from sourcebastion.license_expression import LicensePolicy


@pytest.fixture(autouse=True)
def no_external_scanners():
    with patch("sourcebastion.external_scanners.ExternalScannerManager.scan_all", return_value=[]):
        yield


def project(root, *packages, metadata=()):
    rows = [{"name": name, "version": "1.0.0", **({"license": lic} if lic is not None else {})} for name, lic in packages]
    (root / "composer.lock").write_text(json.dumps({"content-hash": "a" * 32, "packages": rows, "packages-dev": []}))
    for name, headers in metadata:
        directory = root / f"site-packages/{name}-1.0.0.dist-info"
        directory.mkdir(parents=True)
        (directory / "METADATA").write_text(
            "\n".join(["Metadata-Version: 2.4", f"Name: {name}", "Version: 1.0.0", *headers]) + "\n\n"
        )
    return root


def results(root, **policy):
    return check_licenses(str(root), LicensePolicy(**policy))


def by_package(result):
    return {f["package"]: f for f in result["findings"]}


class TestPolicyOverInventory:
    def test_results_per_package(self, tmp_path):
        project(
            tmp_path,
            ("a/mit", ["MIT"]),
            ("a/gpl", ["GPL-3.0-only"]),
            ("a/choice", ["MIT", "GPL-3.0-only"]),
            ("a/none", None),
            ("a/text", ["proprietary"]),
            ("a/isc", ["ISC"]),
        )
        result = results(tmp_path, allowed=["MIT"], denied=["GPL-*"])
        findings = by_package(result)
        assert set(findings) == {"a/gpl", "a/none", "a/text", "a/isc"}
        assert (findings["a/gpl"]["license_result"], findings["a/gpl"]["severity"]) == ("denied", "high")
        assert findings["a/gpl"]["rule_id"] == "license-denied-GPL-3.0-only"
        assert findings["a/none"]["rule_id"] == "license-undetermined-unstated"
        assert findings["a/text"]["rule_id"] == "license-undetermined-unparsed"
        assert findings["a/isc"]["rule_id"] == "license-undetermined-ISC"
        assert result["summary"] | {"unassessed_inputs": None} == {
            "total": 6,
            "declarations_not_assessed": 0,
            "permitted": 2,
            "denied": 1,
            "undetermined": 3,
            "coverage": "complete",
            "unassessed_inputs": None,
            "license_list_version": "3.27.0",
        }

    def test_findings_bind_occurrence_and_evidence_location(self, tmp_path):
        project(tmp_path, ("a/gpl", ["GPL-3.0-only"]))
        finding = results(tmp_path, denied=["GPL-*"])["findings"][0]
        assert (finding["file"], finding["license_locator"]) == ("composer.lock", "/packages/0/license")
        assert finding["occurrence_id"].startswith("occurrence:sha256:")

    def test_deny_only_policy_still_reports_unstated(self, tmp_path):
        project(tmp_path, ("a/none", None), ("a/mit", ["MIT"]))
        findings = by_package(results(tmp_path, denied=["AGPL-*"]))
        assert set(findings) == {"a/none"}

    def test_conjunctive_denial_does_not_escape(self, tmp_path):
        project(tmp_path, metadata=[("both", ["License-Expression: MIT AND GPL-3.0-only"])])
        assert by_package(results(tmp_path, allowed=["MIT"], denied=["GPL*"]))["both"]["license_result"] == "denied"

    def test_rule_ids_are_canonical(self, tmp_path):
        project(tmp_path, ("a/x", ["gpl-3.0-only"]), ("a/y", ["GPL-3.0-ONLY"]))
        assert {f["rule_id"] for f in results(tmp_path, denied=["GPL-*"])["findings"]} == {
            "license-denied-GPL-3.0-only"
        }

    def test_strictest_observation_wins(self, tmp_path):
        project(
            tmp_path,
            metadata=[
                ("classified", ["Classifier: License :: OSI Approved :: MIT License", "Classifier: License :: Other"]),
            ],
        )
        finding = by_package(results(tmp_path, allowed=["MIT"]))["classified"]
        assert finding["license_result"] == "undetermined"
        assert len(finding["all_licenses"]) == 2

    def test_declarations_are_not_reported_as_unstated(self, tmp_path):
        """A manifest names a dependency; it never states that dependency's license."""
        project(tmp_path, ("a/mit", ["MIT"]))
        (tmp_path / "requirements.txt").write_text("six==1.16.0\n")
        result = results(tmp_path, allowed=["MIT"])
        assert result["summary"]["total"] == 1
        assert result["summary"]["declarations_not_assessed"] == 1
        assert result["findings"] == []

    def test_undetermined_severity_can_be_lowered(self, tmp_path):
        project(tmp_path, ("a/none", None))
        inventory = compose_licensed_inventory(str(tmp_path))
        result = evaluate_inventory(inventory, LicensePolicy(), undetermined_severity="low")
        assert result["findings"][0]["severity"] == "low"
        with pytest.raises(ValueError):
            evaluate_inventory(inventory, LicensePolicy(), undetermined_severity="info")

    def test_partial_coverage_is_disclosed(self, tmp_path):
        project(tmp_path, ("a/mit", ["MIT"]))
        (tmp_path / "Pipfile.lock").write_text("{not json")
        summary = results(tmp_path, allowed=["MIT"])["summary"]
        assert summary["coverage"] == "partial"
        assert "Pipfile.lock" in summary["unassessed_inputs"]

    def test_failed_inventory_fails_the_component(self, tmp_path):
        project(tmp_path, ("a/mit", ["MIT"]))
        inventory = compose_licensed_inventory(str(tmp_path))
        failed = inventory.model_copy(update={"stages": inventory.stages.model_copy(update={"inventory": "failed"})})
        with pytest.raises(ScannerExecutionError) as error:
            check_licenses(str(tmp_path), LicensePolicy(), inventory=failed)
        assert error.value.code == "scope_unresolved"

    def test_no_syft_is_ever_executed(self, tmp_path):
        project(tmp_path, ("a/mit", ["MIT"]))
        with patch("subprocess.run", side_effect=AssertionError("no subprocess")), patch(
            "shutil.which", return_value=None
        ):
            assert results(tmp_path, allowed=["MIT"])["summary"]["permitted"] == 1


class TestCli:
    def config(self, root, body):
        path = root / "policy.yaml"
        path.write_text(body)
        return str(path)

    def test_scan_reports_denied_and_undetermined(self, tmp_path):
        project(tmp_path, ("a/gpl", ["GPL-3.0-only"]), ("a/none", None), ("a/mit", ["MIT"]))
        config = self.config(tmp_path, "license_policy:\n  allowed_licenses: [MIT]\n  denied_licenses: [GPL-*]\n")
        result = CliRunner().invoke(main, ["scan", str(tmp_path), "--license-check", "--config", config])
        assert result.exit_code == 0, result.output
        assert "3 package(s) - 1 permitted, 1 denied, 1 undetermined" in result.output
        assert "a/gpl@1.0.0: GPL-3.0-only" in result.output
        assert "a/none@1.0.0: no license stated" in result.output
        assert "coverage is" not in result.output

    def test_ignore_rule_suppresses_by_canonical_id(self, tmp_path):
        project(tmp_path, ("a/gpl", ["gpl-3.0-only"]))
        config = self.config(
            tmp_path,
            "license_policy:\n  denied_licenses: [GPL-*]\n"
            "ignore:\n  - rule_id: license-denied-GPL-3.0-only\n    permanent: true\n    reason: reviewed\n",
        )
        result = CliRunner().invoke(main, ["scan", str(tmp_path), "--license-check", "--config", config])
        assert result.exit_code == 0, result.output
        assert "1 package(s) - 0 permitted, 1 denied" in result.output
        assert "suppressed" in result.output

    def test_declarations_without_a_lock_are_called_out(self, tmp_path):
        project(tmp_path, ("a/mit", ["MIT"]))
        (tmp_path / "requirements.txt").write_text("six==1.16.0\n")
        config = self.config(tmp_path, "license_policy:\n  allowed_licenses: [MIT]\n")
        result = CliRunner().invoke(main, ["scan", str(tmp_path), "--license-check", "--config", config])
        assert "1 declared dependenc(ies) were not license-checked" in result.output

    def test_partial_coverage_warning(self, tmp_path):
        project(tmp_path, ("a/mit", ["MIT"]))
        (tmp_path / "Pipfile.lock").write_text("{not json")
        config = self.config(tmp_path, "license_policy:\n  allowed_licenses: [MIT]\n")
        result = CliRunner().invoke(main, ["scan", str(tmp_path), "--license-check", "--config", config])
        assert "License coverage is partial" in result.output
