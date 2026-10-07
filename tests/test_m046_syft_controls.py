from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from evaluation.m046 import benchmark, syft_control_job
from evaluation.m046.performance_corpus import generate
from evaluation.m046.syft_control_audit import audit, decode
from evaluation.m046 import syft_control_benchmark as controls


@pytest.fixture
def pins(tmp_path):
    oracle = generate({"id": "pins-unit", "kind": "pins", "count": 4, "roots": 2}, tmp_path / "source")
    records = [
        {
            "id": str(index),
            "name": f"m046-dep-{index:06d}",
            "version": "1.0.0",
            "type": "python",
            "purl": f"pkg:pypi/m046-dep-{index:06d}@1.0.0",
            "cpes": [],
            "locations": [{"path": f"/root-{index % 2:03d}/requirements.txt"}],
        }
        for index in range(4)
    ]
    return {"artifacts": records, "descriptor": {"toggle": False}, "files": [], "artifactRelationships": []}, oracle


def test_control_audit_exact_roots_and_cpe_only_equality(pins):
    document, oracle = pins
    on = deepcopy(document)
    on["descriptor"]["toggle"] = True
    on["artifacts"].reverse()
    for row in on["artifacts"]:
        row["cpes"] = [{"cpe": "synthetic"}]
    before, after = audit(document, oracle), audit(on, oracle)
    assert before["non_cpe_document_sha256"] == after["non_cpe_document_sha256"]
    assert before["cpes"] == 0 and after["cpes"] == 4


@pytest.mark.parametrize(
    "mutation", ["missing", "duplicate", "empty-id", "root", "escape", "purl", "version", "extra-location"]
)
def test_control_audit_refuses_identity_and_location_loss(pins, mutation):
    document, oracle = pins
    record = document["artifacts"][0]
    if mutation == "missing":
        document["artifacts"].pop()
    elif mutation == "duplicate":
        document["artifacts"].append(deepcopy(record))
    elif mutation == "empty-id":
        record["id"] = ""
    elif mutation == "root":
        record["locations"][0]["path"] = "/root-001/requirements.txt"
    elif mutation == "escape":
        record["locations"][0]["path"] = "/../root-000/requirements.txt"
    elif mutation == "purl":
        record["purl"] = "pkg:pypi/unrelated@1.0.0"
    elif mutation == "version":
        record["version"] = "2.0.0"
        record["purl"] = "pkg:pypi/m046-dep-000000@2.0.0"
    else:
        record["locations"].append(deepcopy(record["locations"][0]))
    with pytest.raises(ValueError):
        audit(document, oracle)


def test_isolated_audit_entrypoint_imports_no_checkout(pins, tmp_path):
    document, oracle = pins
    raw, reference = tmp_path / "raw.json", tmp_path / "oracle.json"
    raw.write_text(json.dumps(document))
    reference.write_text(json.dumps(oracle))
    script = Path(benchmark.__file__).with_name("syft_control_audit.py")
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(script), "--raw", str(raw), "--oracle", str(reference)],
        cwd="/",
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    assert json.loads(result.stdout)["occurrences"] == 4


@pytest.mark.parametrize("cpes", ["on", "off"])
@pytest.mark.parametrize("mask", [0o022, 0o077])
def test_launcher_exec_preserves_signal_and_raw_descriptor(tmp_path, cpes, mask):
    raw = tmp_path / "raw.json"
    binary = tmp_path / "native-probe"
    binary.write_text(
        f"#!{sys.executable}\nimport json,os,sys\nprint(json.dumps({{'argv':sys.argv[1:],'pid':os.getpid()}}))\n"
    )
    binary.chmod(0o755)
    code = (
        "from evaluation.m046 import syft_control_job as job; "
        "job.BINARY,job.RAW=__import__('sys').argv[1:3]; job.launch(__import__('sys').argv[3])"
    )
    process = subprocess.Popen(
        [sys.executable, "-B", "-c", code, str(binary), str(raw), cpes], stdout=subprocess.PIPE, umask=mask
    )
    stdout, _ = process.communicate(timeout=10)
    assert process.returncode == 0 and stdout == b""
    record = json.loads(raw.read_text())
    assert record["pid"] == process.pid
    assert record["argv"] == [
        "--mode",
        "control",
        "--root",
        "/source",
        "--generate-cpes=" + str(cpes == "on").lower(),
        "--timeout",
        "150s",
    ]
    assert raw.stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize("kind", ["existing", "symlink", "fifo"])
def test_launcher_refuses_preexisting_raw_without_truncation(tmp_path, monkeypatch, kind):
    raw = tmp_path / "raw.json"
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("untouched")
    if kind == "existing":
        raw.write_text("untouched")
    elif kind == "symlink":
        raw.symlink_to(sentinel)
    else:
        os.mkfifo(raw)
    monkeypatch.setattr(syft_control_job, "RAW", str(raw))
    with pytest.raises(FileExistsError):
        syft_control_job.launch("off")
    assert sentinel.read_text() == "untouched"
    if kind == "existing":
        assert raw.read_text() == "untouched"


def test_invalid_toggle_refused_before_file_creation(tmp_path, monkeypatch):
    raw = tmp_path / "raw.json"
    monkeypatch.setattr(syft_control_job, "RAW", str(raw))
    with pytest.raises(ValueError):
        syft_control_job.launch("maybe")
    assert not raw.exists()


@pytest.mark.parametrize(
    "text",
    [
        '{"id":"one","id":"two"}',
        '{"cpes":NaN}',
        '{"cpes":Infinity}',
        '{"metadata":1e999}',
        '{"metadata":-1e999}',
        "{} {}",
    ],
)
def test_audit_decoder_refuses_ambiguous_or_nonfinite_json(text):
    with pytest.raises(ValueError):
        decode(text)


def test_second_arm_infrastructure_abort_preserves_first_and_plan(tmp_path, monkeypatch):
    binary, manifest = tmp_path / "binary", tmp_path / "manifest.json"
    binary.write_bytes(b"synthetic")
    identity = {"synthetic": "test-only"}
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}[__import__("platform").machine()]
    manifest.write_text(
        json.dumps(
            {"architecture": architecture, "binary_sha256": controls.digest(binary), "candidate_sources": identity}
        )
    )
    monkeypatch.setattr(controls, "candidate_source_identity", lambda: identity)
    monkeypatch.setattr(benchmark, "native_elf", lambda _path: None)
    monkeypatch.setattr(benchmark, "docker", lambda *_args: None)
    monkeypatch.setattr(controls, "SPECS", [{"id": "small", "kind": "pins", "count": 4, "roots": 2}])
    calls = []

    def measure(*args):
        calls.append(args[0])
        if len(calls) == 2:
            raise RuntimeError("synthetic cleanup uncertainty")
        return {"resource_sample_valid": False, "exit_code": -9, "budget_status": "exceeded"}

    monkeypatch.setattr(benchmark, "measure", measure)
    output = tmp_path / "output"
    with pytest.raises(RuntimeError, match="cleanup uncertainty"):
        controls.run(binary, manifest, output, 3)
    report = json.loads((output / "report.json").read_text())
    assert report["status"] == "aborted" and report["planned_attempts"] == 6
    assert report["started_attempts"] == 2 and report["completed_attempts"] == 1
    assert report["not_started_attempts"] == 4
    assert report["records"][0]["measurement"]["exit_code"] == -9
    assert report["records"][1]["attempt_status"] == "aborted"
    assert "cleanup uncertainty" in report["abort_error"] and len(calls) == 2


def test_changed_candidate_invalidates_current_pair_before_comparison(tmp_path, monkeypatch):
    binary, manifest = tmp_path / "binary", tmp_path / "manifest.json"
    binary.write_bytes(b"synthetic")
    identity = {"synthetic": "test-only"}
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}[__import__("platform").machine()]
    manifest.write_text(
        json.dumps(
            {"architecture": architecture, "binary_sha256": controls.digest(binary), "candidate_sources": identity}
        )
    )
    calls = []

    def current_identity():
        calls.append(True)
        return identity if len(calls) < 4 else {"synthetic": "changed"}

    monkeypatch.setattr(controls, "candidate_source_identity", current_identity)
    monkeypatch.setattr(benchmark, "native_elf", lambda _path: None)
    monkeypatch.setattr(benchmark, "docker", lambda *_args: None)
    monkeypatch.setattr(controls, "SPECS", [{"id": "small", "kind": "pins", "count": 4, "roots": 2}])
    monkeypatch.setattr(
        benchmark,
        "measure",
        lambda *_args: {"resource_sample_valid": True, "exit_code": 0, "budget_status": "within-measured-bounds"},
    )
    result = subprocess.CompletedProcess(
        [], 0, json.dumps({"cpes": 0, "non_cpe_document_sha256": "same"}).encode(), b""
    )
    monkeypatch.setattr(controls.subprocess, "run", lambda *_args, **_kwargs: result)
    output = tmp_path / "output"
    with pytest.raises(ValueError, match="candidate changed"):
        controls.run(binary, manifest, output, 1)
    report = json.loads((output / "report.json").read_text())
    assert report["status"] == "aborted" and report["completed_attempts"] == 2
    assert all(
        row["candidate_identity_valid"] is False
        and row["comparative_sample_valid"] is False
        and row["correct_resource_sample"] is False
        for row in report["records"]
    )
