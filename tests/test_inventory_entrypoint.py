"""Private ABI/descriptor tests; no real Grype or hosted custody acceptance."""

import copy
import json
import os
from pathlib import Path
import time
from threading import Event

import pytest

from sourcebastion import inventory_entrypoint as entry
from sourcebastion.inventory import dependency_job
from sourcebastion.inventory.contract import Environment, Producer
from sourcebastion.inventory.inputs import InputRefusal
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256


@pytest.fixture
def mounted(tmp_path, monkeypatch):
    control, source, output = (tmp_path / name for name in ("control", "source", "out"))
    for path in (control, source, output):
        path.mkdir(mode=0o700)
    config = DiscoveryConfig()
    record = dict(
        schema_version="sourcebastion.inventory-control/1",
        deadline_monotonic=time.monotonic() + 300,
        source_sha256="a" * 64,
        producer=Producer(
            name="synthetic-controller", version="1", code_sha256="b" * 64,
            registry_sha256=REGISTRY_SHA256, config_sha256=config.sha256,
        ).model_dump(mode="json"),
        discovery=dict(mappings=[], ignored=[], include_depth=64,
                       include_targets=4096, semantic_checks=5_000_000),
        environment=Environment().model_dump(mode="json"),
        runtime=dict(binary_sha256="c" * 64, binary_bytes=1,
                     advisory_files=[["snapshot.json", "d" * 64, 0],
                                     ["6/vulnerability.db", "e" * 64, 0]],
                     advisory_schema="6.1.10", advisory_built="synthetic",
                     version="0.119.0"),
        go_sha256=None,
    )
    monkeypatch.setattr(entry, "CONTROL", control)
    monkeypatch.setattr(entry, "SOURCE", source)
    monkeypatch.setattr(entry, "OUTPUT", output)
    return control, source, output, record


def install(control, record):
    path = control / "job.json"
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(json.dumps(record, allow_nan=False).encode())
    path.chmod(0o444)
    control.chmod(0o555)
    return path


def test_thin_adapter_reuses_one_source_budget_store_and_fixed_runtime(mounted, monkeypatch):
    control, source, output, record = mounted
    started = time.monotonic()
    record["go_sha256"] = "f" * 64
    install(control, record)
    cancelled, observations = Event(), []

    def run(opened, **kwargs):
        observations.append((opened, kwargs))
        assert opened.root == source
        assert kwargs["budget"].deadline == started + 150
        assert kwargs["budget"].deadline == opened.deadline
        assert kwargs["store"].root == output
        assert kwargs["store"].check == kwargs["budget"].check
        assert kwargs["source_sha256"] == record["source_sha256"]
        assert kwargs["producer"].registry_sha256 == REGISTRY_SHA256
        assert kwargs["environment"].policy == "preserve-alternatives"
        assert kwargs["go_runtime"].binary == Path("/usr/local/bin/sourcebastion-go-source")
        assert kwargs["go_runtime"].sha256 == "f" * 64
        assert kwargs["runtime"].binary_sha256 == "c" * 64
        assert kwargs["cancelled"] is cancelled
        return dependency_job.DependencyResult(b'{"synthetic":true}', True)

    monkeypatch.setattr(dependency_job, "run_dependency", run)
    assert entry._run(started, cancelled) == (b'{"synthetic":true}', 0)
    assert len(observations) == 1
    assert observations[0][0].closed
    assert observations[0][1]["store"]._closed


def test_parent_deadline_can_only_shorten_allowance(mounted, monkeypatch):
    control, _, _, record = mounted
    started = time.monotonic()
    record["deadline_monotonic"] = started + 20
    install(control, record)

    def run(_source, **kwargs):
        assert kwargs["budget"].deadline == record["deadline_monotonic"]
        return dependency_job.DependencyResult(b"{}", True)

    monkeypatch.setattr(dependency_job, "run_dependency", run)
    assert entry._run(started, Event())[1] == 0


def test_expired_parent_refuses_before_typed_imports_or_job(mounted, monkeypatch):
    control, _, _, record = mounted
    record["deadline_monotonic"] = time.monotonic() - 1
    install(control, record)
    monkeypatch.setattr(entry, "_typed", lambda _value: pytest.fail("typed imports after expired parent"))
    with pytest.raises(entry.Refusal, match="inventory-entrypoint-deadline"):
        entry._run(time.monotonic(), Event())


def test_import_and_validation_time_does_not_restart_deadline(mounted, monkeypatch):
    control, _, _, record = mounted
    install(control, record)
    clock = [time.monotonic()]
    original = entry._typed

    def slow(value):
        result = original(value)
        clock[0] += 151
        return result

    monkeypatch.setattr(entry.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(entry, "_typed", slow)
    monkeypatch.setattr(dependency_job, "run_dependency", lambda *a, **k: pytest.fail("new allowance"))
    with pytest.raises(entry.Refusal, match="inventory-entrypoint-deadline"):
        entry._run(clock[0], Event())


@pytest.mark.parametrize("target", ["control", "file"])
def test_controller_record_requires_read_only_regular_custody(mounted, target):
    control, _, _, record = mounted
    file = install(control, record)
    (control if target == "control" else file).chmod(0o755 if target == "control" else 0o644)
    with pytest.raises(entry.Refusal, match="inventory-control-unsafe"):
        with entry._Control(lambda: None):
            pytest.fail("writable control accepted")


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory", "hardlink", "oversize"])
def test_nonregular_alias_and_oversize_control_refuse_without_blocking(mounted, kind):
    control, _, output, record = mounted
    path = control / "job.json"
    if kind == "symlink":
        other = output / "target"
        other.write_text("{}")
        path.symlink_to(other)
    elif kind == "fifo":
        os.mkfifo(path, 0o400)
    elif kind == "directory":
        path.mkdir(mode=0o555)
    elif kind == "hardlink":
        other = output / "target"
        other.write_text("{}")
        other.chmod(0o444)
        os.link(other, path)
    else:
        path.write_bytes(b" " * (entry.MAX_CONTROL_BYTES + 1))
        path.chmod(0o444)
    control.chmod(0o555)
    with pytest.raises((entry.Refusal, OSError)):
        with entry._Control(lambda: None):
            pytest.fail("unsafe control accepted")


def test_control_replacement_after_pipeline_keeps_available_evidence(mounted, monkeypatch):
    control, _, output, record = mounted
    file = install(control, record)

    def run(_source, **kwargs):
        kwargs["store"].put("grype.stderr", b"retained synthetic diagnostic")
        control.chmod(0o755)
        file.rename(control / "original")
        replacement = control / "job.json"
        replacement.write_bytes(file_bytes)
        replacement.chmod(0o444)
        control.chmod(0o555)
        return dependency_job.DependencyResult(b"{}", True)

    file_bytes = file.read_bytes()
    monkeypatch.setattr(dependency_job, "run_dependency", run)
    with pytest.raises(entry.Refusal, match="inventory-control-changed"):
        entry._run(time.monotonic(), Event())
    assert (output / "grype.stderr").read_bytes() == b"retained synthetic diagnostic"
    assert (control / "original").read_bytes() == file_bytes


def test_nonempty_output_is_not_cleaned_or_reused(mounted, monkeypatch):
    control, _, output, record = mounted
    install(control, record)
    old = output / "existing"
    old.write_bytes(b"preserve")
    monkeypatch.setattr(dependency_job, "run_dependency", lambda *a, **k: pytest.fail("used old output"))
    with pytest.raises(InputRefusal, match="unexpected-artifact-entry"):
        entry._run(time.monotonic(), Event())
    assert old.read_bytes() == b"preserve"


def test_failed_library_receipt_and_artifacts_survive(mounted, monkeypatch):
    control, _, output, record = mounted
    install(control, record)

    def run(_source, **kwargs):
        kwargs["store"].put("grype.stderr", b"diagnostic")
        return dependency_job.DependencyResult(b'{"synthetic_failure":true}', False)

    monkeypatch.setattr(dependency_job, "run_dependency", run)
    assert entry._run(time.monotonic(), Event()) == (b'{"synthetic_failure":true}', 2)
    assert (output / "grype.stderr").read_bytes() == b"diagnostic"


@pytest.mark.parametrize("validation_call", [2, 3])
def test_late_control_guard_source_change_refuses_finalized_receipt(
    mounted, monkeypatch, validation_call,
):
    control, source, output, record = mounted
    path = source / "requirements.txt"
    path.write_bytes(b"requests==2.32.3\n")
    install(control, record)
    original = entry._Control.validate
    calls, resources = [], []

    def run(opened, **kwargs):
        assert opened.read("requirements.txt").content == b"requests==2.32.3\n"
        kwargs["store"].put("grype.stderr", b"retained synthetic evidence")
        resources.append((opened, kwargs["store"]))
        return dependency_job.DependencyResult(b'{"synthetic_finalized":true}', True)

    def late_guard(self):
        calls.append(None)
        if len(calls) == validation_call:
            assert not resources[0][0].closed
            assert not resources[0][1]._closed
            path.write_bytes(b"requests==2.32.4\n")
        return original(self)

    monkeypatch.setattr(dependency_job, "run_dependency", run)
    monkeypatch.setattr(entry._Control, "validate", late_guard)
    with pytest.raises(InputRefusal, match="changed-input"):
        entry._run(time.monotonic(), Event())
    assert len(calls) >= validation_call
    assert resources[0][0].closed
    assert resources[0][1]._closed
    assert (output / "grype.stderr").read_bytes() == b"retained synthetic evidence"


def test_final_control_guard_artifact_change_refuses_without_cleanup(mounted, monkeypatch):
    control, _, output, record = mounted
    install(control, record)
    original = entry._Control.validate
    calls = []

    def run(_source, **kwargs):
        kwargs["store"].put("grype.stderr", b"retained synthetic evidence")
        return dependency_job.DependencyResult(b"{}", True)

    def late_guard(self):
        calls.append(None)
        if len(calls) == 3:
            (output / "grype.stderr").write_bytes(b"changed synthetic evidence")
        return original(self)

    monkeypatch.setattr(dependency_job, "run_dependency", run)
    monkeypatch.setattr(entry._Control, "validate", late_guard)
    with pytest.raises(InputRefusal, match="changed-artifact-file"):
        entry._run(time.monotonic(), Event())
    assert (output / "grype.stderr").read_bytes() == b"changed synthetic evidence"


@pytest.mark.parametrize("target", ["control", "cancel"])
def test_final_source_recheck_does_not_hide_control_or_cancel_change(mounted, monkeypatch, target):
    from sourcebastion.inventory.inputs import Source

    control, _, _, record = mounted
    file = install(control, record)
    cancelled = Event()
    original = Source.validate

    def late_source(self):
        original(self)
        if target == "control":
            file.chmod(0o644)
        else:
            cancelled.set()

    monkeypatch.setattr(Source, "validate", late_source)
    monkeypatch.setattr(
        dependency_job, "run_dependency",
        lambda *a, **k: dependency_job.DependencyResult(b"{}", True),
    )
    reason = "inventory-control-changed" if target == "control" else "inventory-entrypoint-cancelled"
    with pytest.raises(entry.Refusal, match=reason):
        entry._run(time.monotonic(), cancelled)


@pytest.mark.parametrize("receipt,finalized", [(b"", True), ("{}", True), (b"x" * 65537, True), (b"{}", 1)])
def test_receipt_boundary_is_exact_and_bounded(mounted, monkeypatch, receipt, finalized):
    control, _, _, record = mounted
    install(control, record)
    monkeypatch.setattr(
        dependency_job, "run_dependency",
        lambda *a, **k: dependency_job.DependencyResult(receipt, finalized),
    )
    with pytest.raises(entry.Refusal, match="inventory-entrypoint-receipt-invalid"):
        entry._run(time.monotonic(), Event())


@pytest.mark.parametrize("raw", [
    b'{"schema_version":1,"schema_version":2}', b'{"secret":NaN}',
    b'{"secret":1e9999}', b'{"secret":"\\ud800"}',
    b'{"secret":' + b"9" * 65 + b"}", b"[" * 17 + b"]" * 17,
    b'{"secret":"\xff"}', b"{}", b"null",
])
def test_control_decode_refuses_malformed_and_unbounded_values(raw):
    with pytest.raises((entry.Refusal, ValueError, UnicodeError)):
        entry._decode(raw, lambda: None)


@pytest.mark.parametrize("path,value", [
    (("schema_version",), "unknown"), (("source_sha256",), "A" * 64),
    (("producer", "registry_sha256"), "0" * 64),
    (("producer", "config_sha256"), "0" * 64),
    (("runtime", "binary_bytes"), True), (("runtime", "version"), "other"),
    (("go_sha256",), "/customer/script"),
    (("environment", "platform"), "linux"),
])
def test_strict_typed_controller_fields_do_not_invent_authority(mounted, path, value):
    record = copy.deepcopy(mounted[3])
    target = record
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    with pytest.raises((ValueError, TypeError)):
        entry._typed(record)


@pytest.mark.parametrize("value", [True, False, None, "150", -1, 0, float("inf"), float("nan")])
def test_strict_absolute_deadline(value):
    with pytest.raises(entry.Refusal, match="inventory-control-invalid"):
        entry._deadline(value)


def test_signal_cancellation_and_unknown_errors_are_bounded(mounted, monkeypatch, capfd):
    monkeypatch.setattr(entry.sys, "argv", ["private-inventory-child"])
    observed = []

    def run(_started, cancelled):
        handler = entry.signal.getsignal(entry.signal.SIGTERM)
        handler(entry.signal.SIGTERM, None)
        assert cancelled.is_set()
        observed.append(cancelled)
        raise RuntimeError("customer-sensitive exception text")

    monkeypatch.setattr(entry, "_run", run)
    prior = entry.signal.getsignal(entry.signal.SIGTERM)
    assert entry.main() == 3
    raw = capfd.readouterr()
    value = json.loads(raw.out)
    assert value["reason"] == "inventory-entrypoint-refused"
    assert value["authority"] == "child-artifact-facts-only"
    assert value["kernel_admission"] == "not_observed"
    assert "customer-sensitive" not in raw.out + raw.err
    assert len(observed) == 1
    assert entry.signal.getsignal(entry.signal.SIGTERM) is prior


def test_arguments_cannot_choose_paths_and_refusal_text_is_not_echoed(monkeypatch, capfd):
    monkeypatch.setattr(entry.sys, "argv", ["private-inventory-child", "/customer/secret"])
    assert entry.main() == 3
    assert json.loads(capfd.readouterr().out)["reason"] == "inventory-entrypoint-arguments-refused"
    assert str(entry.Refusal("customer-sensitive")) == "inventory-entrypoint-refused"
