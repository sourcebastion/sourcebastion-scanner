"""Provider facts must not invent canonical roots, versions or coverage."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from evaluation.m046 import provider_evidence as provider
from evaluation.m046.provider_native import audit_child


def document():
    return {
        "descriptor": {"name": "m046-restricted-evidence-provider"},
        "artifacts": [
            {
                "id": "a",
                "name": "debug",
                "version": "4.3.7",
                "purl": "pkg:npm/debug@4.3.7",
                "type": "npm",
                "foundBy": "javascript-lock-cataloger",
                "cpes": [],
                "locations": [{"path": "/a/package-lock.json"}],
                "metadataType": "javascript-npm-package-lock-entry",
                "metadata": {"dependencies": {"ms": "^2.1.3"}},
            },
            {
                "id": "b",
                "name": "ms",
                "version": "2.1.3",
                "purl": "pkg:npm/ms@2.1.3",
                "type": "npm",
                "foundBy": "javascript-lock-cataloger",
                "cpes": [],
                "locations": [{"path": "/a/package-lock.json"}],
                "metadata": {},
            },
        ],
        "artifactRelationships": [{"parent": "b", "child": "a", "type": "dependency-of"}],
    }


def test_raw_facts_keep_provider_ids_direction_paths_and_unreported_axes():
    result = provider.facts(document())
    assert result["records"][0]["paths"] == ["a/package-lock.json"]
    assert result["provider_dependencies"] == [
        {
            "parent_provider_id": "a",
            "child_provider_id": "b",
            "parent": "npm:debug@4.3.7",
            "child": "npm:ms@2.1.3",
            "shared_evidence_paths": ["a/package-lock.json"],
            "canonical_edge": "unassessed",
        }
    ]
    assert result["coverage"] == "unassessed"
    assert "canonical-project-root" in result["unreported_dimensions"]
    assert result["records"][0]["raw_metadata"] == {"dependencies": {"ms": "^2.1.3"}}


def test_cross_root_provider_relation_remains_unassessed_without_invented_root():
    raw = document()
    raw["artifacts"][1]["locations"][0]["path"] = "/b/package-lock.json"
    result = provider.facts(raw)
    assert result["provider_dependencies"][0]["shared_evidence_paths"] == []
    assert result["provider_dependencies"][0]["canonical_edge"] == "unassessed"


@pytest.mark.parametrize("change", ["id", "cataloger", "cpe", "purl", "location", "dangling", "profile"])
def test_bad_provider_raw_is_refused(change):
    raw = document()
    if change == "id":
        raw["artifacts"][1]["id"] = "a"
    elif change == "cataloger":
        raw["artifacts"][0]["foundBy"] = "python-package-cataloger"
    elif change == "cpe":
        raw["artifacts"][0]["cpes"] = [{"cpe": "invented"}]
    elif change == "purl":
        raw["artifacts"][0]["purl"] = None
    elif change == "location":
        raw["artifacts"][0]["locations"] = []
    elif change == "dangling":
        raw["artifactRelationships"][0]["child"] = "unknown"
    else:
        raw["descriptor"]["name"] = "syft"
    with pytest.raises(ValueError):
        provider.facts(raw)


@pytest.mark.parametrize("path", ["/../outside", "//outside", "/a/./file", "/a//file", "/a\\file", "/a/..", "/"])
def test_noncanonical_or_escaping_paths_are_refused(path):
    raw = document()
    raw["artifacts"][0]["locations"][0]["path"] = path
    with pytest.raises(ValueError):
        provider.facts(raw)


def test_same_identity_at_different_paths_stays_two_provider_records():
    raw = document()
    extra = deepcopy(raw["artifacts"][0])
    extra["id"] = "c"
    extra["locations"][0]["path"] = "/b/package-lock.json"
    raw["artifacts"].append(extra)
    result = provider.facts(raw)
    assert len([row for row in result["records"] if row["identity"] == "npm:debug@4.3.7"]) == 2


def test_go_mod_versions_stay_declaration_candidates_not_selected():
    raw = document()
    raw["artifacts"] = [
        {**raw["artifacts"][0], "foundBy": "go-module-file-cataloger", "purl": "pkg:golang/example.test/mod@v1.2.3"}
    ]
    raw["artifactRelationships"] = []
    expected = {"packages": [], "edges": [], "declarations": [], "disposition": "declaration-only"}
    result = provider.comparison(expected, raw)
    assert result["basic"]["missing_packages"] == result["basic"]["extra_packages"] == []
    assert result["declared_version_candidates"] == ["golang:example.test/mod@v1.2.3"]
    assert result["full_contract_qualified"] is False


def test_expected_oracle_cannot_change_extracted_facts():
    raw = document()
    before = deepcopy(raw)
    first = provider.facts(raw)
    provider.comparison(
        {"packages": ["npm:unrelated@0"], "edges": [], "declarations": [], "disposition": "parsed"}, raw
    )
    assert provider.facts(raw) == first and raw == before


def test_complexity_limit_refuses_deep_or_shared_raw():
    raw = document()
    nested = {}
    raw["nested"] = nested
    for _ in range(33):
        nested["child"] = {}
        nested = nested["child"]
    with pytest.raises(ValueError, match="complexity"):
        provider.facts(raw)
    raw = document()
    raw["alias"] = raw["artifacts"]
    with pytest.raises(ValueError, match="shared"):
        provider.facts(raw)


def test_isolated_auditor_runs_outside_project_import_path(tmp_path):
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps(document()))
    (tmp_path / "json.py").write_text('raise RuntimeError("project import")')
    auditor = Path(provider.__file__).with_name("provider_audit.py")
    process = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            str(auditor),
            "--raw",
            str(raw),
            "--fixture",
            "node-npm-edges",
            "--facts-output",
            str(tmp_path / "facts.json"),
        ],
        cwd=tmp_path,
        capture_output=True,
        timeout=30,
    )
    assert process.returncode == 0, process.stderr.decode()
    assert json.loads((tmp_path / "facts.json").read_text())["facts"]["coverage"] == "unassessed"


def test_source_binding_requires_regular_hashed_input_without_claiming_coverage():
    facts = provider.facts(document())
    snapshot = {
        "a/package-lock.json": {"sha256": "a" * 64, "mode": 420},
        "ignored.txt": {"sha256": "b" * 64, "mode": 420},
    }
    bound = provider.bind_sources(facts, snapshot)
    assert bound["observed_path_sha256"] == {"a/package-lock.json": "a" * 64}
    assert bound["coverage"] == "unassessed"
    for bad in ({}, {"symlink": "outside"}, {"directory": True}, {"sha256": "invalid"}):
        with pytest.raises(ValueError, match="not-bound"):
            provider.bind_sources(facts, {"a/package-lock.json": bad})


def test_package_json_is_not_assumed_installed_or_external():
    raw = document()
    raw["artifacts"][0]["foundBy"] = "javascript-package-cataloger"
    record = provider.facts(raw)["records"][0]
    assert record["evidence_kind"] == "package-metadata-role-unassessed"
    assert record["purl"] == "pkg:npm/debug@4.3.7"
    assert record["raw_version"] == "4.3.7"


def test_declaration_edge_cannot_borrow_selected_identity_from_other_provider():
    raw = document()
    declared = deepcopy(raw["artifacts"][0])
    declared.update(id="declared", foundBy="java-pom-cataloger")
    raw["artifacts"][0]["foundBy"] = "java-gradle-lockfile-cataloger"
    raw["artifacts"].append(declared)
    raw["artifactRelationships"] = [{"parent": "b", "child": "declared", "type": "dependency-of"}]
    expected = {"packages": ["npm:debug@4.3.7", "npm:ms@2.1.3"], "edges": [["npm:debug@4.3.7", "npm:ms@2.1.3"]]}
    result = provider.comparison(expected, raw)
    assert result["basic"]["missing_edges"] == [("npm:debug@4.3.7", "npm:ms@2.1.3")]
    assert len(provider.facts(raw)["provider_dependencies"]) == 1


def test_actual_isolated_guardian_launches_auditor(tmp_path):
    with (tmp_path / "stdout").open("wb") as stdout, (tmp_path / "stderr").open("wb") as stderr:
        status = audit_child([sys.executable, "-I", "-B", "-c", "print('auditor-started')"], stdout, stderr)
    assert status == 0, (tmp_path / "stderr").read_text()
    assert (tmp_path / "stdout").read_text() == "auditor-started\n"
