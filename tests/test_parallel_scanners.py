"""Real thread coordination proves overlap, bounds, and failure cleanup."""
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from sourcebastion.external_scanners import ExternalScannerManager, ScannerExecutionError


@pytest.mark.parametrize("raw", [False, True])
def test_three_components_overlap_and_preserve_finding_order(tmp_path, raw):
    barrier = threading.Barrier(3, timeout=3)
    manager = ExternalScannerManager(max_workers=3)

    def scanner(name):
        def scan(_path):
            barrier.wait()
            return [{"rule_id": name}]

        def scan_raw(path):
            findings = scan(path)
            output = tmp_path / (name + ".json")
            output.write_text("{}")
            return findings, str(output)
        return SimpleNamespace(enabled=True, scan=scan, scan_with_raw_output=scan_raw)

    manager.scanners = {name: scanner(name) for name in ["semgrep", "kics", "grype"]}
    if raw:
        findings, outputs = manager.scan_all_with_raw_outputs(".")
        assert list(outputs) == ["semgrep", "kics", "grype"]
        assert all(Path(path).exists() for path in outputs.values())
    else:
        findings = manager.scan_all(".")
    assert [item["rule_id"] for item in findings] == ["semgrep", "kics", "grype"]


def test_failure_cleans_output_from_a_component_that_finishes_later(tmp_path):
    both_running = threading.Barrier(2, timeout=3)
    failure_started = threading.Event()
    late_finished = threading.Event()
    output = tmp_path / "late.json"

    def fail(_path):
        both_running.wait()
        failure_started.set()
        raise ScannerExecutionError("semgrep", "timeout")

    def late(_path):
        both_running.wait()
        assert failure_started.wait(3)
        output.write_text("{}")
        late_finished.set()
        return [], str(output)

    manager = ExternalScannerManager(max_workers=3)
    manager.scanners = {
        "semgrep": SimpleNamespace(enabled=True, scan_with_raw_output=fail),
        "grype": SimpleNamespace(enabled=True, scan_with_raw_output=late),
    }
    with pytest.raises(ScannerExecutionError, match="semgrep scanner failed \\(timeout\\)"):
        manager.scan_all_with_raw_outputs(".")
    assert not output.exists()
    assert late_finished.is_set()


def test_parallelism_environment_is_bounded(monkeypatch):
    monkeypatch.setenv("SOURCEBASTION_SCANNER_WORKERS", "3")
    assert ExternalScannerManager().max_workers == 3
    monkeypatch.setenv("SOURCEBASTION_SCANNER_WORKERS", "4")
    with pytest.raises(ValueError, match="between 1 and 3"):
        ExternalScannerManager()


def test_serial_mode_does_not_start_work_after_failure():
    started = []
    def fail(_path):
        raise ScannerExecutionError("semgrep", "timeout")
    def later(_path):
        started.append(True)
        return []
    manager = ExternalScannerManager(max_workers=1)
    manager.scanners = {
        "semgrep": SimpleNamespace(enabled=True, scan=fail),
        "grype": SimpleNamespace(enabled=True, scan=later),
    }
    with pytest.raises(ScannerExecutionError):
        manager.scan_all(".")
    assert started == []


def test_pending_components_never_exceed_configured_concurrency():
    first_wave = threading.Barrier(3, timeout=3)
    release = threading.Event()
    lock = threading.Lock()
    started = []
    result = []
    errors = []

    def scanner(name):
        def scan(_path):
            with lock:
                started.append(name)
                first = len(started) <= 2
            if first:
                first_wave.wait()
                assert release.wait(3)
            return [{"rule_id": name}]
        return SimpleNamespace(enabled=True, scan=scan)

    manager = ExternalScannerManager(max_workers=2)
    manager.scanners = {name: scanner(name) for name in ["a", "b", "c", "d", "e"]}

    def run():
        try:
            result.extend(manager.scan_all("."))
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=run)
    thread.start()
    try:
        first_wave.wait()
        assert len(started) == 2
    finally:
        release.set()
        thread.join(timeout=3)
    assert not thread.is_alive()
    assert errors == []
    assert [item["rule_id"] for item in result] == ["a", "b", "c", "d", "e"]


def test_parallel_mode_skips_disabled_scanners_and_normalizes_errors():
    def fail(_path):
        raise RuntimeError("private tool diagnostic")
    manager = ExternalScannerManager(max_workers=3)
    manager.scanners = {
        "disabled": SimpleNamespace(enabled=False),
        "semgrep": SimpleNamespace(enabled=True, scan=fail),
    }
    with pytest.raises(ScannerExecutionError, match=r"semgrep scanner failed \(execution_failed\)") as error:
        manager.scan_all(".")
    assert "private" not in str(error.value)


@pytest.mark.parametrize("workers", [False, 0, 4, 1.5, "3"])
def test_explicit_parallelism_rejects_invalid_bounds(workers):
    with pytest.raises(ValueError, match="between 1 and 3"):
        ExternalScannerManager(max_workers=workers)
