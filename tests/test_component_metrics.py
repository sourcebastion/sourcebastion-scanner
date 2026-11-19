"""M066 S01/T05 (D12): per-component elapsed time and labelled peak memory."""

import hashlib
import json

import pytest

from sourcebastion import incremental_contract as ic
from sourcebastion.external_scanners import GitleaksScanner, ScannerExecutionError
from sourcebastion.incremental_contract import IncrementalContractError, validate_result_envelope
from tests.test_incremental_contract import SCANNER_IMAGE, _canonical, _full_plan, _source_tree


def _run(tmp_path, monkeypatch, *, enabled=True, scan=lambda self, path: []):
    source, head_sha = _source_tree(tmp_path)
    plan = _full_plan(head_sha)
    monkeypatch.setattr(GitleaksScanner, "scan_current_tree", scan)
    if enabled:
        monkeypatch.setenv(ic.COMPONENT_METRICS_ENV, "1")
    else:
        monkeypatch.delenv(ic.COMPONENT_METRICS_ENV, raising=False)
    return ic.execute_scan_plan(str(source), plan, scanner_image=SCANNER_IMAGE), plan


def test_metrics_are_omitted_unless_the_platform_declares_support(tmp_path, monkeypatch):
    envelope, _plan = _run(tmp_path, monkeypatch, enabled=False)
    assert "component_metrics" not in envelope  # older platforms check keys exactly


def test_each_run_component_gets_bounded_elapsed_time(tmp_path, monkeypatch):
    envelope, plan = _run(tmp_path, monkeypatch)
    metric = envelope["component_metrics"]["gitleaks"]
    assert 0 <= metric["elapsed_seconds"] <= ic.MAX_COMPONENT_SECONDS
    assert metric["memory"] in ("partial", "unavailable")
    assert (metric["memory"] == "unavailable") == ("peak_rss_bytes" not in metric)
    validate_result_envelope(envelope, plan)  # digest covers the metrics


def test_a_failed_component_is_still_timed(tmp_path, monkeypatch):
    def fail(self, path):
        raise ScannerExecutionError("gitleaks", "scan_timeout")
    envelope, _plan = _run(tmp_path, monkeypatch, scan=fail)
    assert envelope["components"][0]["diagnostic_code"] == "scan_timeout"
    assert "elapsed_seconds" in envelope["component_metrics"]["gitleaks"]


@pytest.mark.parametrize("elapsed, before, after, expected", [
    (1.5, 100, 200, {"elapsed_seconds": 1.5, "memory": "partial", "peak_rss_bytes": 200}),
    (1.5, 200, 200, {"elapsed_seconds": 1.5, "memory": "unavailable"}),  # no new high: unknown, not zero
    (1.5, None, None, {"elapsed_seconds": 1.5, "memory": "unavailable"}),  # parallel: not attributable
    (1.5, 0, 1 << 41, {"elapsed_seconds": 1.5, "memory": "unavailable"}),
    (1801.0, 1, 2, None),
    (float("nan"), 1, 2, None),
    (-1.0, 1, 2, None),
])
def test_memory_is_labelled_and_never_a_fake_zero(elapsed, before, after, expected):
    assert ic._component_metric(elapsed, before, after) == expected


def _with(envelope, plan, metrics):
    body = {k: v for k, v in envelope.items() if k != "result_digest"}
    body["component_metrics"] = metrics
    return {**body, "result_digest": hashlib.sha256(_canonical(body)).hexdigest()}


@pytest.mark.parametrize("metrics", [
    {"semgrep": {"elapsed_seconds": 1.0, "memory": "unavailable"}},  # not planned
    {"gitleaks": {"elapsed_seconds": 1.0, "memory": "measured"}},
    {"gitleaks": {"elapsed_seconds": 1.0, "memory": "unavailable", "peak_rss_bytes": 0}},
    {"gitleaks": {"elapsed_seconds": True, "memory": "unavailable"}},
    {"gitleaks": {"elapsed_seconds": 1.0, "memory": "unavailable", "path": "a.py"}},
    [],
])
def test_invalid_metrics_reject_the_envelope(tmp_path, monkeypatch, metrics):
    envelope, plan = _run(tmp_path, monkeypatch, enabled=False)
    with pytest.raises(IncrementalContractError, match="result_envelope_invalid"):
        validate_result_envelope(_with(envelope, plan, metrics), plan)


def test_metrics_carry_no_repository_text(tmp_path, monkeypatch):
    envelope, _plan = _run(tmp_path, monkeypatch)
    rendered = json.dumps(envelope["component_metrics"])
    assert "app.py" not in rendered and str(tmp_path) not in rendered
