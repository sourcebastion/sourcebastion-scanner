"""Meaningful raw-identity, refusal and preparation boundaries for direct probes."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from evaluation.m046 import benchmark, cyclonedx_export, direct_audit, direct_benchmark, direct_job, direct_prepare
from evaluation.m046.performance_corpus import generate
from evaluation.m046.static_cli import failed

PROVENANCE = {
    "producer": "independent-test",
    "code_sha256": "1" * 64,
    "registry_sha256": "2" * 64,
    "config_sha256": "3" * 64,
    "environment_policy": "unknown",
}


@pytest.fixture
def pins(tmp_path):
    source = tmp_path / "source"
    oracle = generate({"id": "small-independent-pins", "kind": "pins", "count": 12, "roots": 3}, source)
    return source, oracle


@pytest.mark.parametrize("mode", sorted(benchmark.DIRECT_ENGINES))
def test_direct_raw_output_matches_independent_selected_pin_root_oracle(pins, mode):
    source, oracle = pins
    content, status = direct_job.candidate(mode, source, PROVENANCE)
    assert status == 0
    result = direct_audit.audit(json.loads(content), oracle, mode)
    assert len(result.pop("canonical_inventory_sha256")) == 64
    assert result == {
        "status": "exact-synthetic-pin-identities-and-roots",
        "identities": 12,
        "occurrences": 12,
    }


def test_direct_mode_refuses_before_opening_source(tmp_path):
    with pytest.raises(ValueError, match="explicit"):
        direct_job.candidate("unknown", tmp_path / "missing", PROVENANCE)


def test_export_refusal_reports_failed_export_without_inventing_inventory_failure(pins, monkeypatch):
    source, _oracle = pins
    monkeypatch.setattr(cyclonedx_export, "MAX_NODES", 1)
    content, status = direct_job.candidate("direct-cyclonedx", source, PROVENANCE)
    result = json.loads(content)
    assert status == 2
    assert result["inventory_status"] == "complete"
    assert result["sbom_status"] == "failed"
    assert result["matching_status"] == "not-run"
    assert result["reason"] == "sbom-input-complexity-exceeded"
    assert "not-assessed" in result["inventory_retention"]


@pytest.mark.parametrize("change", ["root", "package", "source", "invented-edge"])
def test_inventory_audit_refuses_identity_root_source_or_graph_changes(pins, change):
    source, oracle = pins
    content, _status = direct_job.candidate("direct-inventory", source, PROVENANCE)
    document = json.loads(content)
    if change == "root":
        document["semantic_dimensions"]["occurrences"][0]["root"] = "wrong-root"
    elif change == "package":
        document["semantic_dimensions"]["occurrences"][0]["package"] = "pypi:wrong@1"
    elif change == "source":
        document["semantic_dimensions"]["inputs"][0]["sha256"] = "0" * 64
    else:
        document["edges"].append(["fake", "edge"])
    with pytest.raises(ValueError):
        direct_audit.audit(document, oracle, "direct-inventory")


@pytest.mark.parametrize(
    "change", ["ref", "purl", "evidence", "evidence-line", "evidence-ref", "duplicate-property", "graph"]
)
def test_cyclonedx_audit_refuses_changed_ids_or_lost_source_evidence(pins, change):
    source, oracle = pins
    content, _status = direct_job.candidate("direct-cyclonedx", source, PROVENANCE)
    document = json.loads(content)
    component = document["components"][0]
    if change == "ref":
        component["bom-ref"] = "wrong"
    elif change == "purl":
        component["purl"] = "pkg:pypi/wrong@1"
    elif change == "evidence":
        component["evidence"]["occurrences"][0]["location"] = "wrong.txt"
    elif change == "evidence-line":
        component["evidence"]["occurrences"][0]["line"] = 999
    elif change == "evidence-ref":
        component["evidence"]["occurrences"][0]["bom-ref"] = "wrong-ref"
    elif change == "duplicate-property":
        component["properties"].append(deepcopy(component["properties"][0]))
    else:
        document["dependencies"] = [{"ref": component["bom-ref"], "dependsOn": []}]
    with pytest.raises(ValueError):
        direct_audit.audit(document, oracle, "direct-cyclonedx")


@pytest.mark.parametrize("reason", ["changed-source-root", "input-deadline-exceeded", "malformed-input", "unknown"])
def test_unknown_failure_never_becomes_controlled_large_refusal(pins, reason):
    _source, oracle = pins
    oracle["spec"]["count"] = 100000
    for mode in benchmark.DIRECT_ENGINES:
        with pytest.raises(ValueError, match="malformed refusal"):
            direct_audit.audit(
                {**failed(reason), "refusal_stage": "inventory-evaluation", "source_inventory_status": "failed"},
                oracle,
                mode,
            )


def test_only_expected_large_refusal_shape_is_admitted(pins):
    _source, oracle = pins
    document = {
        **failed("inventory-output-budget-exceeded"),
        "refusal_stage": "inventory-serialization",
        "source_inventory_status": "complete",
    }
    with pytest.raises(ValueError):
        direct_audit.audit(document, oracle, "direct-inventory")
    oracle["spec"]["count"] = 100000
    assert direct_audit.audit(document, oracle, "direct-inventory")["status"] == "controlled-refusal"
    for key, value in [
        ("packages", ["invented"]),
        ("sbom_status", "complete"),
        ("matching_status", "complete"),
        ("schema_version", "future"),
    ]:
        changed = {**document, key: value}
        with pytest.raises(ValueError):
            direct_audit.audit(changed, oracle, "direct-inventory")


def test_isolated_audit_cli_uses_only_trusted_code_path(pins, tmp_path):
    source, _oracle = pins
    content, _status = direct_job.candidate("direct-inventory", source, PROVENANCE)
    raw = tmp_path / "raw.json"
    raw.write_bytes(content)
    process = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            str(Path(direct_audit.__file__)),
            "--raw",
            str(raw),
            "--oracle",
            str(source.with_suffix(".oracle.json")),
            "--mode",
            "direct-inventory",
        ],
        cwd=source,
        capture_output=True,
        timeout=30,
    )
    assert process.returncode == 0, process.stderr.decode()
    assert json.loads(process.stdout)["occurrences"] == 12


def test_direct_commands_keep_runtime_image_policy_and_safe_interpreter_flags():
    for mode in benchmark.DIRECT_ENGINES:
        assert benchmark.command(mode, "python") == [
            "/usr/local/bin/python3",
            "-I",
            "-B",
            "/candidate/app/direct_job.py",
            mode,
        ]
    identity = direct_prepare.source_identity()
    assert "requirements-export.txt" in identity["export_inputs"]
    assert {"schemas/bom-1.6.schema.json", "schemas/spdx.schema.json", "schemas/jsf-0.82.schema.json"} <= set(
        identity["export_inputs"]
    )


def test_successful_direct_arms_retain_equal_full_inventory(pins):
    source, oracle = pins
    documents = {
        mode: json.loads(direct_job.candidate(mode, source, PROVENANCE)[0]) for mode in benchmark.DIRECT_ENGINES
    }
    digests = {
        mode: direct_audit.audit(document, oracle, mode)["canonical_inventory_sha256"]
        for mode, document in documents.items()
    }
    assert len(set(digests.values())) == 1
    sbom = documents["direct-cyclonedx"]
    retained = next(row for row in sbom["metadata"]["properties"] if row["name"] == "sourcebastion:m046:inventory")
    inventory = json.loads(retained["value"])
    inventory["semantic_dimensions"]["fidelity"]["environment"] = "invented"
    retained["value"] = json.dumps(inventory)
    assert (
        direct_audit.audit(sbom, oracle, "direct-cyclonedx")["canonical_inventory_sha256"]
        != digests["direct-inventory"]
    )


@pytest.mark.parametrize("field", ["refusal_stage", "source_inventory_status"])
def test_inventory_output_refusal_cannot_claim_wrong_stage_or_parsing_failure(pins, field):
    _source, oracle = pins
    oracle["spec"]["count"] = 100000
    document = {
        **failed("inventory-output-budget-exceeded"),
        "refusal_stage": "inventory-serialization",
        "source_inventory_status": "complete",
    }
    document[field] = "wrong"
    with pytest.raises(ValueError, match="unexpected refusal stage"):
        direct_audit.audit(document, oracle, "direct-inventory")


def test_runtime_source_map_is_verified_and_truncated_killed_attempt_is_invalid():
    import platform

    packages = {
        name: {"version": version, "sources": {"synthetic.py": "a" * 64}}
        for name, version in direct_prepare.VERSIONS.items()
    }
    manifest = {"expected_packages": packages}
    runtime = {"python": "3.14.8", "architecture": platform.machine(), "packages": packages}
    assert direct_benchmark.runtime_identity(json.dumps(runtime).encode(), manifest, {"exit_code": 0}) == runtime
    changed = deepcopy(runtime)
    changed["packages"]["packaging"]["sources"]["synthetic.py"] = "b" * 64
    with pytest.raises(ValueError, match="identity mismatch"):
        direct_benchmark.runtime_identity(json.dumps(changed).encode(), manifest, {"exit_code": -9})
    for partial in (b"", b'{"python":'):
        assert direct_benchmark.runtime_identity(partial, manifest, {"exit_code": -9}) is None
        with pytest.raises(ValueError, match="unavailable"):
            direct_benchmark.runtime_identity(partial, manifest, {"exit_code": 0})


def test_source_uncertainty_invalidates_previously_paired_exact_records(monkeypatch):
    monkeypatch.setattr(direct_benchmark, "source_identity", lambda: {"epoch": "changed"})
    rows = [
        {
            "candidate_identity_valid": True,
            "exact_resource_sample": True,
            "controlled_refusal": False,
            "comparative_sample_valid": True,
            "paired_canonical_inventory_equal": True,
        }
    ]
    with pytest.raises(ValueError, match="candidate changed"):
        direct_benchmark.assert_identity({"epoch": "original"}, {}, rows)
    assert rows == [
        {
            "candidate_identity_valid": False,
            "exact_resource_sample": False,
            "controlled_refusal": False,
            "comparative_sample_valid": False,
            "paired_canonical_inventory_equal": True,
        }
    ]


def test_bounded_auditor_timeout_retains_invalid_result_without_aborting_plan(monkeypatch, tmp_path):
    def timed_out(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(direct_benchmark.subprocess, "run", timed_out)
    result = direct_benchmark.bounded_audit(tmp_path / "raw.json", tmp_path / "oracle.json", "direct-inventory")
    assert "audit" not in result
    assert "30" in result["audit_error"]
