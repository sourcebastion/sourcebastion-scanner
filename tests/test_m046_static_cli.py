"""Serialization and isolated entrypoint boundaries for synthetic evaluation."""

import json
from pathlib import Path
import subprocess
import sys

import pytest

from evaluation.m046.static_cli import encode
from evaluation.m046.static_inputs import InputRefusal
from evaluation.m046.static_native import trace_admission


def test_serialization_boundary_includes_newline_and_ascii_escaping():
    document = {"path": "café.txt", "packages": ["pypi:foo@1"]}
    output = encode(document)
    assert output.endswith(b"\n") and json.loads(output) == document
    assert encode(document, limit=len(output)) == output
    with pytest.raises(InputRefusal, match="inventory-output-budget-exceeded"):
        encode(document, limit=len(output) - 1)


def test_serialization_cannot_outlive_shared_deadline():
    with pytest.raises(InputRefusal, match="input-deadline-exceeded"):
        encode({"packages": ["pypi:foo@1"]}, deadline=0)


@pytest.mark.parametrize("call", ["execveat(3,", "sendmmsg(3,", "socketpair(AF_UNIX,", "clone3(", "fork("])
def test_native_trace_gate_refuses_alternative_process_and_network_calls(call):
    trace = '7 execve("/trusted/python", ["python"], 0x1) = 0\n8 ' + call
    with pytest.raises(ValueError, match="static-native-process-or-network-attempt"):
        trace_admission(trace, "/trusted/python")


def test_native_trace_gate_ignores_syscall_names_inside_literal_filenames():
    trace = '7 execve("/trusted/python", ["python"], 0x1) = 0\n7 openat(AT_FDCWD, "/source/socket(AF_UNIX,requirements.txt", O_RDONLY) = 3\n'
    assert trace_admission(trace, "/trusted/python") == (["/trusted/python"], 0)


def test_native_trace_gate_retains_initial_unfinished_calls():
    trace = '[pid 7] execve("/trusted/python", ["python"], 0x1) = 0\n[pid 8] socket(AF_INET, SOCK_STREAM, 0 <unfinished ...>\n[pid 8] <... socket resumed>) = 3\n'
    with pytest.raises(ValueError, match="static-native-process-or-network-attempt"):
        trace_admission(trace, "/trusted/python")


def test_isolated_entrypoint_does_not_import_customer_named_modules(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "requirements.txt").write_text("foo==1\n")
    for name in ("packaging.py", "json.py", "sitecustomize.py"):
        (source / name).write_text('raise RuntimeError("source-executed")\n')
    script = Path(__file__).resolve().parents[1] / "evaluation/m046/static_cli.py"
    completed = subprocess.run(
        [sys.executable, "-I", str(script), "--root", str(source)],
        cwd=source,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0 and completed.stderr == b""
    assert json.loads(completed.stdout)["packages"] == ["pypi:foo@1"]


def test_missing_root_emits_bounded_failure_without_os_path(tmp_path):
    missing = tmp_path / "private-root"
    script = Path(__file__).resolve().parents[1] / "evaluation/m046/static_cli.py"
    completed = subprocess.run(
        [sys.executable, "-I", str(script), "--root", str(missing)],
        capture_output=True,
        timeout=10,
        check=False,
    )
    document = json.loads(completed.stdout)
    assert completed.returncode == 2 and completed.stderr == b""
    assert document["inventory_status"] == "failed" and document["packages"] == []
    assert document["refusal_codes"] == ["unavailable-source-root"]
    assert str(missing).encode() not in completed.stdout


def test_cli_reports_numeric_complexity_without_traceback(tmp_path):
    (tmp_path / "requirements.txt").write_text("foo==1\nfoo>=" + "9" * 4301 + "\n")
    script = Path(__file__).resolve().parents[1] / "evaluation/m046/static_cli.py"
    completed = subprocess.run(
        [sys.executable, "-I", str(script), "--root", str(tmp_path)], capture_output=True, timeout=10, check=False
    )
    document = json.loads(completed.stdout)
    assert completed.returncode == 0 and completed.stderr == b""
    assert document["inventory_status"] == "partial" and document["packages"] == []
    (record,) = document["semantic_dimensions"]["inputs"]
    assert record["reason"] == "requirement-complexity-budget-exceeded"
