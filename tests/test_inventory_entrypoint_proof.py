"""Mocked CI ownership/retention boundaries; no Docker or scan is executed."""

import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
from types import SimpleNamespace

import pytest

HERE = Path(__file__).resolve().parents[1] / "scripts"
driver = runpy.run_path(str(HERE / "run-inventory-entrypoint-proof.py"), run_name="pure_driver_tests")
image_helper = runpy.run_path(str(HERE / "verify-inventory-entrypoint.py"), run_name="pure_verifier_tests")
IMAGE = "sha256:" + "e" * 64
CID = "c" * 64


def fake_runner(proof, failure=None):
    calls = []

    def run(command, label, *, seconds):
        assert 0 < seconds <= 180
        calls.append(command)
        action = command[1]
        if action == "create":
            path = Path(command[command.index("--cidfile") + 1])
            path.write_text("invalid" if failure == "invalid-cid" else CID + "\n")
            (proof / (label + ".stdout")).write_text("d" * 64 if failure == "id-mismatch" else CID + "\n")
            if failure == "create-timeout":
                raise TimeoutError("synthetic-first-create")
            return 1 if failure == "create-return" else 0
        if action == "inspect":
            after = label.endswith("after")
            (proof / (label + ".stdout")).write_text(json.dumps([
                dict(Id=CID, Image="sha256:" + "f" * 64 if failure == "image-mismatch" else IMAGE,
                     State=dict(Running=bool(after and failure == "running"), ExitCode=0)),
            ]))
            return 1 if after and failure == "final-inspect-return" else 0
        if action == "start":
            if failure == "start-timeout":
                raise TimeoutError("synthetic-first-start")
            return 1 if failure in {"start-return", "start-and-remove"} else 0
        assert action == "rm" and command == ["docker", "rm", "--force", CID]
        if failure in {"remove-timeout", "start-and-remove"}:
            raise TimeoutError("synthetic-later-cleanup")
        return 1 if failure == "remove-return" else 0

    return run, calls


def test_owned_success_binds_exact_image_id_and_removes_only_fresh_cid(tmp_path):
    run, calls = fake_runner(tmp_path)
    facts = driver["owned_container"](run, tmp_path, "case", [], IMAGE, ["synthetic"], seconds=180)
    assert facts == dict(label="case", image_id=IMAGE, container_id=CID, exit_code=0, remove_exit_code=0)
    assert calls[-1] == ["docker", "rm", "--force", CID]
    assert [row[1] for row in calls] == ["create", "inspect", "start", "inspect", "rm"]


@pytest.mark.parametrize("failure", [
    "create-return", "create-timeout", "id-mismatch", "image-mismatch", "start-return",
    "start-timeout", "final-inspect-return", "running", "remove-return", "remove-timeout",
])
def test_every_admitted_cid_error_attempts_bounded_cleanup_and_retains_failure(tmp_path, failure):
    run, calls = fake_runner(tmp_path, failure)
    sentinel = tmp_path / "existing-evidence"
    sentinel.write_bytes(b"retain original evidence")
    with pytest.raises((ValueError, TimeoutError)):
        driver["owned_container"](run, tmp_path, "case", [], IMAGE, ["synthetic"], seconds=180)
    assert calls[-1] == ["docker", "rm", "--force", CID]
    assert sentinel.read_bytes() == b"retain original evidence"
    facts = json.loads((tmp_path / "case-owned-container.json").read_bytes())
    assert facts["container_id"] == CID
    assert "first_failure" in facts or "cleanup_failure" in facts


def test_later_cleanup_failure_preserves_first_failure(tmp_path):
    run, calls = fake_runner(tmp_path, "start-and-remove")
    with pytest.raises(ValueError, match="owned-container-nonzero"):
        driver["owned_container"](run, tmp_path, "case", [], IMAGE, ["synthetic"], seconds=180)
    facts = json.loads((tmp_path / "case-owned-container.json").read_bytes())
    assert facts["first_failure"] == "ValueError" and facts["cleanup_failure"] == "TimeoutError"
    assert calls[-1][-1] == CID


def test_cid_admission_error_preserves_original_create_failure(tmp_path):
    calls = []

    def run(command, label, *, seconds):
        calls.append(command)
        assert command[1] == "create"
        Path(command[command.index("--cidfile") + 1]).write_bytes(b"\xff")
        raise TimeoutError("synthetic-original-create-timeout")

    with pytest.raises(TimeoutError, match="synthetic-original-create-timeout"):
        driver["owned_container"](run, tmp_path, "case", [], IMAGE, ["synthetic"], seconds=180)
    facts = json.loads((tmp_path / "case-owned-container.json").read_bytes())
    assert facts["first_failure"] == "TimeoutError"
    assert facts["cid_admission_failure"] == "UnicodeDecodeError"
    assert len(calls) == 1


@pytest.mark.parametrize("mode", ["O", "OO", "environment"])
def test_optimized_verifier_refuses_before_any_product_import(mode):
    # Execute only this negative guard. The finder prevents all product imports
    # even on the old unsafe script, so no composition/Grype/candidate runs.
    script = HERE / "verify-inventory-entrypoint.py"
    wrapper = """
import importlib.abc, runpy, sys
class ProductImportBarrier(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'sourcebastion' or fullname.startswith('sourcebastion.'):
            raise RuntimeError('product-import-before-optimization-refusal')
sys.meta_path.insert(0, ProductImportBarrier())
script = sys.argv[1]
sys.argv = [script, 'prepare']
runpy.run_path(script, run_name='__main__')
"""
    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    flags = ["-I", "-" + mode] if mode != "environment" else []
    if mode == "environment":
        environment["PYTHONOPTIMIZE"] = "1"
    result = subprocess.run(
        [sys.executable, *flags, "-c", wrapper, str(script)],
        env=environment, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode != 0
    assert "optimized-probe-runtime-refused" in result.stderr
    assert "product-import-before-optimization-refusal" not in result.stderr


@pytest.mark.parametrize("kind", ["file", "symlink", "dangling"])
def test_preexisting_cid_path_never_adopts_or_removes_a_container(tmp_path, kind):
    path = tmp_path / "case.cid"
    if kind == "file":
        path.write_text(CID)
    else:
        path.symlink_to(tmp_path / ("existing" if kind == "symlink" else "missing"))
        if kind == "symlink":
            (tmp_path / "existing").write_text(CID)
    run, calls = fake_runner(tmp_path)
    with pytest.raises(ValueError, match="cidfile-already-exists"):
        driver["owned_container"](run, tmp_path, "case", [], IMAGE, ["synthetic"], seconds=180)
    assert not calls


def test_invalid_cid_never_starts_or_removes_an_unbound_container(tmp_path):
    run, calls = fake_runner(tmp_path, "invalid-cid")
    with pytest.raises(ValueError, match="owned-container-create-failed"):
        driver["owned_container"](run, tmp_path, "case", [], IMAGE, ["synthetic"], seconds=180)
    assert [row[1] for row in calls] == ["create"]
    facts = json.loads((tmp_path / "case-owned-container.json").read_bytes())
    assert "no-admitted-cid" in facts["ownership"]


def test_private_file_reader_keeps_exact_bytes_and_refuses_aliases(tmp_path):
    path = tmp_path / "fact"
    path.write_bytes(b"finite original bytes")
    assert image_helper["read"](path, 64) == b"finite original bytes"
    with pytest.raises(AssertionError):
        image_helper["read"](path, 1)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        image_helper["read"](link, 64)


@pytest.mark.parametrize("raw", [b"", b"x" * 65537])
def test_host_documents_refuse_empty_and_oversize_transport(tmp_path, raw):
    path = tmp_path / "doc"
    path.write_bytes(raw)
    with pytest.raises(ValueError, match="document-bound"):
        driver["bounded_json"](path)


@pytest.mark.parametrize("mode", ["complete", "stdout-overflow", "stderr-overflow", "stalled", "cleanup-failure"])
def test_capture_requires_complete_bounded_output_and_keeps_first_error(tmp_path, monkeypatch, mode):
    capture = driver["capture"]
    globals_ = capture.__globals__
    killed, clock = [], [0.0]

    class Pipe:
        def __init__(self, number):
            self.number, self.closed = number, False

        def fileno(self):
            return self.number

        def close(self):
            self.closed = True

    class Process:
        pid = 123456789
        stdout, stderr = Pipe(100), Pipe(101)
        finished = False

        def poll(self):
            return 0 if self.finished else None

        def wait(self, *, timeout):
            assert timeout > 0
            if mode == "cleanup-failure":
                raise TimeoutError("synthetic-cleanup-error")
            self.finished = True
            return 0

    process = Process()
    overflow = mode in {"stdout-overflow", "stderr-overflow", "cleanup-failure"}
    payload = b"x" * 65537 if overflow else b"synthetic complete receipt"
    chunks = {100: [], 101: []}
    chunks[101 if mode == "stderr-overflow" else 100] = [payload[i:i + 8192] for i in range(0, len(payload), 8192)]

    class Selector:
        def __init__(self):
            self.rows = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def register(self, file, _events, data):
            self.rows[file] = SimpleNamespace(fileobj=file, data=data)

        def unregister(self, file):
            del self.rows[file]

        def get_map(self):
            return self.rows

        def select(self, timeout):
            clock[0] += max(0.01, timeout)
            return [] if mode == "stalled" else [(key, 1) for key in list(self.rows.values())]

    def popen(command, **kwargs):
        assert command == ["synthetic-mocked-client"]
        assert kwargs["start_new_session"] and kwargs["stdin"] == -3
        return process

    monkeypatch.setitem(globals_, "subprocess", SimpleNamespace(Popen=popen, DEVNULL=-3, PIPE=-1))
    monkeypatch.setitem(globals_, "selectors", SimpleNamespace(DefaultSelector=Selector, EVENT_READ=1))
    monkeypatch.setitem(globals_, "os", SimpleNamespace(
        read=lambda fd, _maximum: chunks[fd].pop(0) if chunks[fd] else b"",
        killpg=lambda pid, signal: killed.append((pid, signal)),
    ))
    monkeypatch.setitem(globals_, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    out, err = tmp_path / "stdout", tmp_path / "stderr"
    if mode == "complete":
        assert capture(["synthetic-mocked-client"], out, err, seconds=1) == 0
        assert out.read_bytes() == payload and err.read_bytes() == b""
        assert not killed
    else:
        with pytest.raises(TimeoutError if mode == "stalled" else ValueError) as caught:
            capture(["synthetic-mocked-client"], out, err, seconds=2)
        assert len(out.read_bytes()) <= 65536 and len(err.read_bytes()) <= 65536
        assert killed and killed[0][0] == process.pid
        if mode == "cleanup-failure":
            assert "capture-overflow" in str(caught.value)
            assert "cleanup-failed:TimeoutError" in caught.value.__notes__[0]
    assert process.stdout.closed and process.stderr.closed
