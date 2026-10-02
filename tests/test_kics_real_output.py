"""KICS parsing, asserted against output KICS actually produced.

The wrapper read `queryName`, `results` and `file`. KICS emits `query_name`,
`files` and `file_name`. The occurrence loop therefore never ran: no
repository ever received a KICS finding, and nothing failed to say so.

Every existing KICS fixture was written by hand in the shape the parser
expected, so the tests agreed with the bug. The fixture here is a captured
document from the pinned KICS in the published image, which is the only kind
of fixture that could have caught this.
"""

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from sourcebastion.external_scanners import KicsScanner

FIXTURE = Path(__file__).parent / "fixtures" / "scanners" / "kics" / "real-output.json"


@pytest.fixture
def real_output():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _scan_with(document, tmp_path):
    """Run the wrapper against a canned KICS document."""
    scanner = KicsScanner()

    def write_report(command, **_kwargs):
        # KICS writes results.json into the directory given after -o.
        output_dir = Path(command[command.index("-o") + 1])
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "results.json").write_text(json.dumps(document))
        return subprocess.CompletedProcess(command, 0, "", "")

    with (
        patch.object(scanner, "is_installed", return_value=True),
        patch.object(scanner, "_find_assets_path", return_value=tmp_path),
        patch("sourcebastion.external_scanners.subprocess.run", side_effect=write_report),
    ):
        return scanner.scan(str(tmp_path))


def test_the_fixture_is_real_kics_output(real_output):
    """Guard the fixture itself: hand-written JSON is what hid the bug."""
    assert real_output["kics_version"].startswith("v")
    query = real_output["queries"][0]
    assert "query_name" in query and "queryName" not in query
    assert "files" in query and "results" not in query
    assert "file_name" in query["files"][0]


def test_real_output_produces_findings(real_output, tmp_path):
    """The regression. This returned an empty list for every repository."""
    findings = _scan_with(real_output, tmp_path)
    assert findings, "KICS findings were discarded"


def test_high_severity_iac_findings_survive(real_output, tmp_path):
    findings = _scan_with(real_output, tmp_path)
    titles = {finding["title"] for finding in findings}
    assert "Unrestricted Security Group Ingress" in titles
    assert "Sensitive Port Is Exposed To Entire Network" in titles


def test_findings_name_their_file_and_line(real_output, tmp_path):
    """`file` read a key KICS does not emit, so every path was "unknown"."""
    findings = _scan_with(real_output, tmp_path)
    # Asserted before the all() checks below, which are vacuously true on an
    # empty list -- exactly the state this module exists to catch.
    assert findings
    assert all(finding["file"] != "unknown" for finding in findings), findings
    assert all(finding["file"].endswith("main.tf") for finding in findings)
    assert all(isinstance(finding["line"], int) for finding in findings)


def test_info_severity_is_still_skipped(real_output, tmp_path):
    """The INFO filter must keep working now that occurrences are counted."""
    findings = _scan_with(real_output, tmp_path)
    assert findings  # not vacuous: the disjointness below needs real findings
    info_titles = {
        query["query_name"]
        for query in real_output["queries"]
        if query["severity"] == "INFO"
    }
    assert info_titles  # the fixture contains INFO queries
    assert not (info_titles & {finding["title"] for finding in findings})


def test_the_legacy_shape_still_parses(tmp_path):
    """A document in the old shape degrades to a parse, not to silence.

    Both spellings are accepted deliberately: if some future KICS renames
    these again, the failure should be visible rather than an empty result.
    """
    legacy = {
        "queries": [
            {
                "queryName": "Legacy Shaped Query",
                "description": "d",
                "severity": "HIGH",
                "results": [{"file": "main.tf", "line": 7}],
            }
        ]
    }
    findings = _scan_with(legacy, tmp_path)
    assert [finding["title"] for finding in findings] == ["Legacy Shaped Query"]
    assert findings[0]["file"] == "main.tf"
