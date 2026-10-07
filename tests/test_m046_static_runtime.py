"""Source/ABI/image-authority and durable failure boundaries for runtime proof."""

import json
import os
from pathlib import Path
import subprocess
import sys
import stat

import pytest

from evaluation.m046 import benchmark, static_runtime


@pytest.mark.parametrize(
    "changed", ["runtime_profile", "cgo_enabled", "architecture", "candidate_sources", "binary_sha256", "static_elf"]
)
def test_preparation_mismatch_precedes_build_or_source_execution(tmp_path, monkeypatch, changed):
    monkeypatch.setattr(static_runtime, "candidate_source_identity", lambda: {"source": "current"})
    monkeypatch.setattr(static_runtime, "digest", lambda _path: "current")
    monkeypatch.setattr(static_runtime, "validate", lambda _path: {"static": True})
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}[static_runtime.platform.machine()]
    manifest = {
        "runtime_profile": "static",
        "cgo_enabled": "0",
        "architecture": architecture,
        "candidate_sources": {"source": "current"},
        "binary_sha256": "current",
        "static_elf": {"static": True},
    }
    manifest[changed] = "wrong"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    output = tmp_path / "evidence"
    with pytest.raises(ValueError, match="preparation identity mismatch"):
        static_runtime.run(tmp_path / "binary", path, output)
    assert not output.exists()


def test_preparation_failure_retains_full_plan_and_zero_started_attempts(tmp_path, monkeypatch):
    identity = {"source": "current"}
    monkeypatch.setattr(static_runtime, "candidate_source_identity", lambda: identity)
    monkeypatch.setattr(static_runtime, "digest", lambda _path: "current")
    monkeypatch.setattr(static_runtime, "validate", lambda _path: {"static": True})
    monkeypatch.setattr(static_runtime, "context", lambda *_args: (_ for _ in ()).throw(ValueError("prep refused")))
    monkeypatch.setattr(static_runtime, "checked", lambda *_args: None)
    identifier = "1" * 64

    def fake_docker(*args):
        if args[0] == "ps":
            return identifier
        if args[0] == "inspect":
            return json.dumps([{"Image": "sha256:" + "2" * 64}])
        return json.dumps([{"Id": "sha256:" + "2" * 64, "Architecture": "amd64"}])

    monkeypatch.setattr(benchmark, "docker", fake_docker)
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}[static_runtime.platform.machine()]
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "runtime_profile": "static",
                "cgo_enabled": "0",
                "architecture": architecture,
                "candidate_sources": identity,
                "binary_sha256": "current",
                "static_elf": {"static": True},
            }
        )
    )
    output = tmp_path / "evidence"
    with pytest.raises(ValueError, match="prep refused"):
        static_runtime.run(tmp_path / "binary", path, output)
    report = json.loads((output / "report.json").read_text())
    assert report["status"] == "aborted"
    assert report["planned_attempts"] == report["not_started_attempts"] == 64
    assert report["started_attempts"] == report["completed_attempts"] == 0


def test_runtime_cannot_use_mutable_image_or_override_legacy_resource_image(tmp_path):
    for engine, image in ((benchmark.SYFT_RUNTIME_ENGINE, "scanner:latest"), ("syft", "sha256:" + "1" * 64)):
        with pytest.raises(ValueError):
            benchmark.measure(engine, {}, tmp_path, tmp_path / "output", "python", runtime_image=image)
    assert not (tmp_path / "output").exists()


def test_runtime_launcher_route_is_explicit_and_frontend_closure_is_trusted():
    command = benchmark.command(benchmark.SYFT_RUNTIME_ENGINE, "ignored")
    assert command == ["/usr/local/bin/python3", "-I", "-B", "/harness/syft_control_job.py", "extended"]
    root = Path(static_runtime.__file__).parent
    assert all((root / name).is_file() for name in static_runtime.FRONTEND)
    assert "static_cli.py" in static_runtime.FRONTEND


def test_identity_process_has_its_own_deadline_after_host_driver_disappears():
    script = "from evaluation.m046.runtime_inspect import guard; import signal; guard(1); signal.pause()"
    result = subprocess.run(
        [sys.executable, "-B", "-c", script], cwd=Path(static_runtime.__file__).parents[2], timeout=3
    )
    assert result.returncode == 124


def test_restrictive_host_umask_cannot_make_copied_runtime_code_unreadable(tmp_path):
    previous = os.umask(0o077)
    try:
        root = tmp_path / "context"
        code = root / "frontend/evaluation/m046"
        code.mkdir(parents=True)
        (code / "static_cli.py").write_text("trusted code")
        (root / "m046-syft").write_bytes(b"native executable")
        (root / "runtime_inspect.py").write_text("trusted inspector")
        static_runtime.normalize_context(root)
    finally:
        os.umask(previous)
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o755 for path in (root, *root.rglob("*")) if path.is_dir())
    assert stat.S_IMODE((code / "static_cli.py").stat().st_mode) == 0o644
    assert stat.S_IMODE((root / "runtime_inspect.py").stat().st_mode) == 0o644
    assert stat.S_IMODE((root / "m046-syft").stat().st_mode) == 0o755
