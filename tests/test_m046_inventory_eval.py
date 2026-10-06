"""Independent checks for evaluator boundaries, semantics and measurement."""

import copy
import json
import os
from pathlib import Path
import sys
import time

import pytest

from evaluation.m046.corpus import CORPUS
from evaluation.m046.run import compare, execute, identity, materialize, normalize, projection, snapshot, validate_case
from evaluation.m046.summarize import summarize


def test_oracle_has_required_ecosystems_and_unique_cases():
    assert len(CORPUS) >= 40
    assert len({fixture["id"] for fixture in CORPUS}) == len(CORPUS)
    assert {fixture["ecosystem"] for fixture in CORPUS} >= {
        "python",
        "node",
        "go",
        "rust",
        "java",
        "dotnet",
        "ruby",
        "php",
    }
    assert {fixture["expected"]["disposition"] for fixture in CORPUS} >= {
        "parsed",
        "declaration-only",
        "unsupported",
        "malformed",
        "unsafe",
        "ignored",
    }
    for fixture in CORPUS:
        validate_case(fixture)


@pytest.mark.parametrize("path", ["../escape.txt", "/tmp/escape.txt", "a/../../escape.txt"])
def test_materializer_refuses_path_escape(tmp_path, path):
    fixture = copy.deepcopy(CORPUS[0])
    fixture["files"] = {path: "requests==2.32.3\n"}
    with pytest.raises(ValueError, match="unsafe fixture path"):
        materialize(fixture, tmp_path / "source")
    assert not (tmp_path / "source").exists()


def test_materializer_refuses_arbitrary_symlink_target(tmp_path):
    fixture = copy.deepcopy(CORPUS[-2])
    fixture["symlinks"] = {"requirements.txt": "/etc/passwd"}
    with pytest.raises(ValueError, match="unapproved synthetic symlink"):
        materialize(fixture, tmp_path / "source")


def test_projected_hash_lock_retains_original_provenance(tmp_path):
    fixture = next(fixture for fixture in CORPUS if fixture["id"] == "python-custom-hashed-lock")
    root = tmp_path / "source"
    materialize(fixture, root)
    original = (root / "dependencies-prod.txt").read_bytes()
    mappings = projection(root)
    assert len(mappings) == 1
    assert mappings[0]["original"] == "dependencies-prod.txt"
    assert (root / mappings[0]["projected"]).read_text() == "requests==2.32.3\n"
    assert (root / "dependencies-prod.txt").read_bytes() == original


@pytest.mark.parametrize(
    "content",
    [
        "-c constraints.txt\n",
        "-r base.txt\n",
        "requests>=2\n",
        'requests==2.32.3; os_name=="posix"\n',
        "Please discuss requests==2.32.3.\n",
    ],
)
def test_projection_refuses_unsupported_semantics_and_prose(tmp_path, content):
    root = tmp_path / "source"
    root.mkdir()
    (root / "custom.in").write_text(content)
    assert projection(root) == []


def test_projection_does_not_follow_escape_or_cycle(tmp_path):
    root = tmp_path / "source"
    materialize(CORPUS[-2], root)
    before = snapshot(root)
    assert projection(root) == []
    assert snapshot(root) == before


def test_projection_does_not_turn_constraint_target_into_installed_package(tmp_path):
    fixture = next(fixture for fixture in CORPUS if fixture["id"] == "python-constraint-only")
    root = tmp_path / "source"
    materialize(fixture, root)
    assert projection(root) == []


def test_pep503_normalization_keeps_ecosystem_namespace_and_version():
    assert identity("pkg:pypi/Typing_Extensions@4.12.2") == "pypi:typing-extensions@4.12.2"
    assert identity("pkg:npm/%40scope/lib@1.2.3?arch=x86_64") == "npm:@scope/lib@1.2.3"
    assert identity("pkg:golang/golang.org/x/text@v0.18.0") == "golang:golang.org/x/text@v0.18.0"
    assert identity("pkg:pypi/requests") is None


def test_syft_dependency_of_direction_excludes_file_ownership():
    document = {
        "artifacts": [{"id": "ms", "purl": "pkg:npm/ms@2.1.3"}, {"id": "debug", "purl": "pkg:npm/debug@4.3.7"}],
        "artifactRelationships": [
            {"parent": "ms", "child": "debug", "type": "dependency-of"},
            {"parent": "debug", "child": "file", "type": "contains"},
        ],
    }
    assert normalize(document, "syft")["edges"] == [["npm:debug@4.3.7", "npm:ms@2.1.3"]]


def test_cyclonedx_edges_require_evidenced_package_endpoints():
    document = {
        "components": [
            {"bom-ref": "debug", "purl": "pkg:npm/debug@4.3.7"},
            {"bom-ref": "ms", "purl": "pkg:npm/ms@2.1.3"},
        ],
        "dependencies": [{"ref": "debug", "dependsOn": ["ms", "missing"]}, {"ref": "root", "dependsOn": ["debug"]}],
    }
    assert normalize(document, "cdxgen")["edges"] == [["npm:debug@4.3.7", "npm:ms@2.1.3"]]


def test_empty_output_cannot_claim_coverage_or_declaration_success():
    expected = next(fixture["expected"] for fixture in CORPUS if fixture["id"] == "python-constraint-only")
    result = compare(expected, {"packages": [], "edges": []})
    assert result["missing_packages"] == []
    assert result["coverage"] == "unassessed"
    assert result["declarations"] == "unassessed"


def test_non_object_json_output_is_rejected():
    with pytest.raises(ValueError, match="JSON object"):
        normalize([], "syft")


def test_summary_does_not_count_a_partial_failed_repeat_as_agreement():
    record = {
        "fixture": "sample",
        "expected": {"packages": []},
        "observed": {"packages": [], "edges": []},
        "comparison": {"missing_packages": [], "extra_packages": [], "missing_edges": [], "extra_edges": []},
        "metrics": {"exit_code": 0, "timed_out": False, "wall_seconds": 1, "max_child_rss_kib": 100},
        "source_unchanged": True,
    }
    failed = copy.deepcopy(record)
    failed["metrics"]["exit_code"] = 1
    failed.pop("observed")
    report = {
        "records": [record, failed],
        "engine": "sample",
        "binary_sha256": "binary",
        "corpus_sha256": "corpus",
        "architecture": "test",
    }
    result = summarize(report)
    assert result["exact_package_edge_agreements"] == 0
    assert result["fixtures"]["sample"]["repeat_equal"] is None
    assert result["coverage_assessment"] == "pending"


@pytest.mark.integration
def test_native_sandbox_denies_network_source_writes_and_inherited_secrets(tmp_path, monkeypatch):
    tracer = os.environ.get("M046_STRACE")
    if not tracer:
        pytest.skip("opt-in native namespace proof requires M046_STRACE")
    source, scratch = tmp_path / "source", tmp_path / "run"
    source.mkdir()
    scratch.mkdir()
    monkeypatch.setenv("M046_PRIVATE_SENTINEL", "must-not-inherit")
    code = """import json, os, socket
result={"secret": "M046_PRIVATE_SENTINEL" in os.environ}
try:
    open("MUTATED", "w").write("bad")
    result["write"]="accepted"
except OSError as error:
    result["write"]=error.errno
try:
    socket.create_connection(("1.1.1.1", 443), timeout=1)
    result["network"]="accepted"
except OSError as error:
    result["network"]=error.errno
print(json.dumps(result))
"""
    result = execute(source, scratch, Path(tracer), [sys.executable, "-c", code], 10)
    assert result["exit_code"] == 0, (scratch / "stderr.log").read_text()
    observed = json.loads((scratch / "stdout.log").read_text())
    assert observed == {"secret": False, "write": 30, "network": 101}
    assert not (source / "MUTATED").exists()


@pytest.mark.integration
def test_native_sandbox_deadline_stops_process_tree(tmp_path):
    tracer = os.environ.get("M046_STRACE")
    if not tracer:
        pytest.skip("opt-in native namespace proof requires M046_STRACE")
    source, scratch = tmp_path / "source", tmp_path / "run"
    source.mkdir()
    scratch.mkdir()
    child_pid_file = scratch / "child-host-pid"
    # A new session evades a parent-only process-group kill. PID namespace
    # teardown must still kill it, and this proof checks its host /proc entry.
    code = f"""import os, time
from pathlib import Path
if os.fork() == 0:
    os.setsid()
    status = Path("/proc/self/status").read_text()
    host_pid = next(line.split()[1] for line in status.splitlines() if line.startswith("NSpid:"))
    Path({str(child_pid_file)!r}).write_text(host_pid)
time.sleep(60)
"""
    result = execute(source, scratch, Path(tracer), [sys.executable, "-c", code], 1)
    assert result["timed_out"]
    assert result["exit_code"] == -9
    assert result["wall_seconds"] < 5
    child = Path("/proc") / child_pid_file.read_text()
    deadline = time.monotonic() + 2
    while child.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not child.exists(), "descendant survived namespace teardown"
