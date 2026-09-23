"""Executable contract tests for the reviewed release workflow."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "release.yml"
BUILD_JOBS = (
    "build-docker-standard",
    "build-docker-slim",
    "build-docker-micro",
    "build-docker-thin",
    "build-docker-semgrep",
)


@dataclass(frozen=True)
class ValidationResult:
    returncode: int
    stdout: str
    stderr: str
    release_sha: str
    github_output: str


def load_workflow() -> dict:
    return yaml.load(WORKFLOW_PATH.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def validation_script() -> str:
    steps = load_workflow()["jobs"]["prepare-release"]["steps"]
    return next(step["run"] for step in steps if step.get("id") == "release_metadata")


def test_release_requires_manual_dispatch_and_protected_environment():
    workflow = load_workflow()
    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert workflow["jobs"]["prepare-release"]["environment"] == "release"

    steps = workflow["jobs"]["prepare-release"]["steps"]
    create = next(step for step in steps if step["name"].startswith("Create the draft"))
    assert create["if"] == "steps.release_metadata.outputs.release_exists != 'true'"


def run_validation(
    tmp_path: Path,
    *,
    release_state: str = "",
    gh_exit: int = 1,
    create_tag: bool = False,
) -> ValidationResult:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Release Test"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "release@example.invalid"], cwd=tmp_path, check=True)
    (tmp_path / "VERSION").write_text("1.7.31\n", encoding="utf-8")
    subprocess.run(["git", "add", "VERSION"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=tmp_path, check=True)
    release_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    if create_tag:
        subprocess.run(["git", "tag", "v1.7.31"], cwd=tmp_path, check=True)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_gh = fake_bin / "gh"
    fake_gh.write_text(
        "#!/bin/sh\n"
        "if [ -n \"${FAKE_RELEASE_STATE:-}\" ]; then\n"
        "  printf '%s\\n' \"$FAKE_RELEASE_STATE\"\n"
        "fi\n"
        "exit \"${FAKE_GH_EXIT:-1}\"\n",
        encoding="utf-8",
    )
    fake_gh.chmod(0o755)
    output = tmp_path / "github-output"
    env = os.environ.copy()
    env.update(
        {
            "FAKE_GH_EXIT": str(gh_exit),
            "FAKE_RELEASE_STATE": release_state.replace("{sha}", release_sha),
            "GITHUB_OUTPUT": str(output),
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": release_sha,
            "PATH": f"{fake_bin}:{env['PATH']}",
            "REQUESTED_VERSION": "v1.7.31",
        }
    )
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", validation_script()],
        cwd=tmp_path,
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return ValidationResult(
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        release_sha=release_sha,
        github_output=output.read_text() if output.exists() else "",
    )


def test_new_release_validation_records_a_new_draft(tmp_path: Path):
    result = run_validation(tmp_path)

    assert result.returncode == 0, result.stderr
    assert "release_exists=false" in result.github_output
    assert "release_version=1.7.31" in result.github_output
    assert f"release_sha={result.release_sha}" in result.github_output


def test_matching_draft_release_is_resumable(tmp_path: Path):
    result = run_validation(
        tmp_path,
        release_state="true\t{sha}",
        gh_exit=0,
    )

    assert result.returncode == 0, result.stderr
    assert "release_exists=true" in result.github_output


@pytest.mark.parametrize(
    ("release_state", "create_tag", "error"),
    (
        ("false\tplaceholder", False, "already published"),
        ("true\tplaceholder", False, "not"),
        ("", True, "without a resumable draft"),
    ),
)
def test_release_validation_rejects_nonresumable_versions(
    tmp_path: Path, release_state: str, create_tag: bool, error: str
):
    result = run_validation(
        tmp_path,
        release_state=release_state,
        gh_exit=0 if release_state else 1,
        create_tag=create_tag,
    )

    assert result.returncode != 0
    assert error in result.stderr


def test_builds_publish_only_run_scoped_staging_tags():
    jobs = load_workflow()["jobs"]

    for job_name in BUILD_JOBS:
        job = jobs[job_name]
        assert job["outputs"]["image_digest"] == "${{ steps.build.outputs.digest }}"
        build = next(step for step in job["steps"] if step.get("id") == "build")
        tags = build["with"]["tags"]
        assert "release-${{ github.run_id }}-${{ github.run_attempt }}" in tags
        assert ":latest" not in tags
        assert ":v${{" not in tags
        assert ":${{ needs.prepare-release.outputs.release_sha }}" not in tags
        assert build["with"]["provenance"] == "mode=max"
        assert build["with"]["sbom"] == "true"
        assert any(step.get("uses", "").startswith("actions/attest@") for step in job["steps"])


def test_digest_scan_and_all_variants_gate_public_tag_promotion():
    jobs = load_workflow()["jobs"]
    release_scan = jobs["release-scan"]
    scan_commands = "\n".join(step.get("run", "") for step in release_scan["steps"])
    scan_environment = "\n".join(
        str(step.get("env", {}).get("RELEASE_IMAGE", "")) for step in release_scan["steps"]
    )
    assert "needs.build-docker-standard.outputs.image_digest" in scan_environment
    assert ":v${VERSION}" not in scan_commands

    promotion = jobs["promote-images"]
    assert set(promotion["needs"]) == {
        "prepare-release",
        *BUILD_JOBS,
        "release-scan",
    }
    promote_script = next(
        step["run"] for step in promotion["steps"] if "Promote tested digests" in step["name"]
    )
    for tag in (":v${VERSION}", ":latest", ":slim", ":micro", ":thin", ":semgrep"):
        assert tag in promote_script
    assert "^sha256:[0-9a-f]{64}$" in promote_script
    assert "promote-images" in jobs["update-github-release"]["needs"]


def test_retired_semantic_release_runtime_is_absent():
    for path in (".releaserc.json", "package.json", "package-lock.json"):
        assert not (ROOT / path).exists()
