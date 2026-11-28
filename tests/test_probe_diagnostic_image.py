"""M066 S01/T05: the probe-diagnostic image is diagnostics-only and built FROM a release digest."""

import os
import subprocess
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SHIM = ROOT / "images" / "diagnostic" / "opengrep"
JOB = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text())["jobs"]["build-diagnostic-image"]


def _shim(tmp_path):
    real = tmp_path / "real-opengrep"
    real.write_text('#!/bin/sh\necho "real $*"\n')
    real.chmod(0o755)
    shim = tmp_path / "opengrep"
    shim.write_text(SHIM.read_text().replace("/usr/local/bin/opengrep", str(real)))
    shim.chmod(0o755)
    return shim


def test_version_probe_is_delayed_then_answered_by_the_real_tool(tmp_path):
    env = {**os.environ, "SOURCEBASTION_DIAGNOSTIC_PROBE_DELAY_SECONDS": "1"}
    started = time.monotonic()
    out = subprocess.run([str(_shim(tmp_path)), "--version", "--metrics=off"], env=env,
                         capture_output=True, text=True, check=True)
    assert time.monotonic() - started >= 1
    assert out.stdout.strip() == "real --version --metrics=off"


def test_scans_are_not_delayed(tmp_path):
    env = {**os.environ, "SOURCEBASTION_DIAGNOSTIC_PROBE_DELAY_SECONDS": "30"}
    started = time.monotonic()
    out = subprocess.run([str(_shim(tmp_path)), "scan", "--oss-only"], env=env,
                         capture_output=True, text=True, check=True, timeout=10)
    assert time.monotonic() - started < 5
    assert out.stdout.strip() == "real scan --oss-only"


def test_default_delay_exceeds_the_default_probe_ceiling():
    from sourcebastion.external_scanners import probe_timeout_seconds
    assert ":-45}" in SHIM.read_text() and 45 > probe_timeout_seconds()


def test_release_job_builds_from_the_promoted_digest_and_never_tags_latest():
    assert "promote-images" in JOB["needs"] and "build-docker-standard" in JOB["needs"]
    build = next(step for step in JOB["steps"] if step.get("id") == "build")
    assert build["with"]["file"] == "./images/diagnostic/Dockerfile"
    assert "@${{ needs.build-docker-standard.outputs.image_digest }}" in build["with"]["build-args"]
    tags = build["with"]["tags"]
    assert "-diagnostic:" in tags and "latest" not in tags
    dockerfile = (ROOT / "images" / "diagnostic" / "Dockerfile").read_text()
    assert "FROM ${RELEASE_IMAGE}" in dockerfile and "USER root" not in dockerfile
