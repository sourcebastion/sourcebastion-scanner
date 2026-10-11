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
DOCKER_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "docker.yml"
CONTAINER_RUNNER_PATH = ROOT / "scripts" / "run-scanner-container.sh"
HOSTED_SMOKE_PATH = ROOT / "scripts" / "smoke-scan-hosted.sh"
BUILD_JOBS = ("build-docker-standard",)


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


def test_release_supports_bot_dispatch_and_audited_manual_release():
    workflow = load_workflow()
    assert set(workflow["on"]) == {"repository_dispatch", "workflow_dispatch"}
    assert workflow["on"]["repository_dispatch"]["types"] == ["scanner-release"]
    manual_inputs = workflow["on"]["workflow_dispatch"]["inputs"]
    assert manual_inputs["version"]["required"] == "true"
    assert manual_inputs["release_reason"]["required"] == "true"
    assert workflow["jobs"]["prepare-release"]["environment"] == "release"

    steps = workflow["jobs"]["prepare-release"]["steps"]
    validate = next(step for step in steps if step.get("id") == "release_metadata")
    assert "github.event.client_payload.version" in validate["env"]["REQUESTED_VERSION"]
    assert validate["env"]["RELEASE_REASON"] == "${{ inputs.release_reason }}"
    assert (
        'if [ "$GITHUB_ACTOR" != "sourcebastion-bot[bot]" ]; then'
        in validate["run"]
    )
    assert 'if [ "$GITHUB_ACTOR" != "jfelten" ]; then' in validate["run"]
    assert "${#RELEASE_REASON}" in validate["run"]
    create = next(step for step in steps if step["name"].startswith("Create the draft"))
    assert create["if"] == "steps.release_metadata.outputs.release_exists != 'true'"
    assert create["env"]["VERSION"] == (
        "${{ steps.release_metadata.outputs.release_version }}"
    )


def run_validation(
    tmp_path: Path,
    *,
    release_state: str = "",
    gh_exit: int = 1,
    create_tag: bool = False,
    event_name: str = "repository_dispatch",
    actor: str = "sourcebastion-bot[bot]",
    release_reason: str = "",
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
            "GITHUB_ACTOR": actor,
            "GITHUB_EVENT_NAME": event_name,
            "RELEASE_REASON": release_reason,
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


@pytest.mark.parametrize(
    ("event_name", "actor", "error"),
    (
        ("workflow_dispatch", "sourcebastion-bot[bot]", "owner jfelten"),
        ("repository_dispatch", "jfelten", "sourcebastion-bot[bot]"),
    ),
)
def test_release_validation_rejects_untrusted_dispatchers(
    tmp_path: Path, event_name: str, actor: str, error: str
):
    result = run_validation(tmp_path, event_name=event_name, actor=actor)

    assert result.returncode != 0
    assert error in result.stderr


def test_manual_release_requires_a_meaningful_reason(tmp_path: Path):
    rejected = run_validation(
        tmp_path,
        event_name="workflow_dispatch",
        actor="jfelten",
        release_reason="too short",
    )
    assert rejected.returncode != 0
    assert "meaningful audit reason" in rejected.stderr


def test_manual_release_with_reason_passes_validation(tmp_path: Path):
    result = run_validation(
        tmp_path,
        event_name="workflow_dispatch",
        actor="jfelten",
        release_reason="dispatching by hand while the initiator is down",
    )
    assert result.returncode == 0, result.stderr


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
        assert job["permissions"]["artifact-metadata"] == "write"
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
    assert scan_commands.count('scripts/run-scanner-container.sh "$RELEASE_IMAGE"') == 3

    container_runner = CONTAINER_RUNNER_PATH.read_text(encoding="utf-8")
    assert '--user "$(id -u):$(id -g)"' in container_runner
    assert "-e HOME=/tmp" in container_runner
    assert '-v "$PWD:/scan"' in container_runner

    promotion = jobs["promote-images"]
    assert set(promotion["needs"]) == {
        "prepare-release",
        *BUILD_JOBS,
        "release-scan",
        "hosted-scan",
    }
    promote_script = next(
        step["run"] for step in promotion["steps"] if "Promote tested digests" in step["name"]
    )
    for tag in (":v${VERSION}", ":latest"):
        assert tag in promote_script
    assert "^sha256:[0-9a-f]{64}$" in promote_script
    assert "promote-images" in jobs["update-github-release"]["needs"]


def test_pr_ci_exercises_the_release_scanner_runtime():
    workflow = yaml.load(
        DOCKER_WORKFLOW_PATH.read_text(encoding="utf-8"), Loader=yaml.BaseLoader
    )
    steps = workflow["jobs"]["build-scanner"]["steps"]
    smoke = next(step for step in steps if step["name"] == "Exercise release scanner runtime")
    command = smoke["run"]

    assert 'printf \'six==1.17.0\\n\'' in command
    assert '"$GITHUB_WORKSPACE/scripts/run-scanner-container.sh"' in command
    assert "scan . --sbom --sbom-output scan-results/sbom.cdx.json" in command
    assert "test -d .grype-deps" in command
    assert "test -s scan-results/scan.json" in command
    assert "test -s scan-results/sbom.cdx.json" in command


def test_release_sbom_is_required_and_written_to_real_files():
    workflow = load_workflow()
    steps = workflow["jobs"]["release-scan"]["steps"]
    sbom = next(step for step in steps if step["name"] == "Generate SBOM")

    assert sbom.get("continue-on-error") is None
    assert "--output scan-results/sbom-scan.json" in sbom["run"]
    assert "--output /dev/null" not in sbom["run"]
    assert "test -s scan-results/sbom.cdx.json" in sbom["run"]


def test_container_runner_maps_host_identity_and_checkout(tmp_path: Path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    captured = tmp_path / "docker-args"
    fake_docker = fake_bin / "docker"
    fake_docker.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CAPTURED_ARGS\"\n",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)
    env = os.environ.copy()
    env.update(
        {
            "CAPTURED_ARGS": str(captured),
            "PATH": f"{fake_bin}:{env['PATH']}",
        }
    )

    subprocess.run(
        [str(CONTAINER_RUNNER_PATH), "scanner@sha256:test", "github-scan", "."],
        cwd=tmp_path,
        env=env,
        check=True,
    )

    assert captured.read_text(encoding="utf-8").splitlines() == [
        "run",
        "--rm",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "-e",
        "HOME=/tmp",
        "-v",
        f"{tmp_path}:/scan",
        "-w",
        "/scan",
        "scanner@sha256:test",
        "github-scan",
        ".",
    ]


def test_retired_semantic_release_runtime_is_absent():
    for path in (".releaserc.json", "package.json", "package-lock.json"):
        assert not (ROOT / path).exists()


# --- the initiator -----------------------------------------------------------

DISPATCH_WORKFLOW = ROOT / ".github" / "workflows" / "release-dispatch.yml"


def _dispatch_workflow():
    return yaml.load(DISPATCH_WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def test_something_actually_sends_the_bot_dispatch():
    """`release.yml` accepted a dispatch nobody sent.

    The `repository_dispatch` path required `sourcebastion-bot[bot]`, but the
    initiator was semantic-release, removed in the same commit that added the
    gate. So the documented process -- maintainer dispatch -- ran through an
    input named `break_glass_reason`, and the automated path was unreachable.
    """
    workflow = _dispatch_workflow()
    steps = workflow["jobs"]["dispatch"]["steps"]
    script = "\n".join(step.get("run", "") for step in steps)
    assert "event_type=scanner-release" in script, (
        "the initiator must send the event type release.yml listens for"
    )
    assert "client_payload[version]" in script, (
        "release.yml reads the version from client_payload"
    )


def test_the_initiator_triggers_on_a_version_bump_reaching_main():
    workflow = _dispatch_workflow()
    push = workflow["on"]["push"]
    assert push["branches"] == ["main"]
    assert push["paths"] == ["VERSION"], (
        "a release is declared by a VERSION change; a broader trigger would "
        "request a release on unrelated pushes"
    )


def test_the_initiator_token_is_scoped_to_this_repository():
    """Same constraint as every other App token here.

    `create-github-app-token` scopes to the current repository only when both
    `owner` and `repositories` are omitted; `owner` with an empty
    `repositories` scopes to every repository the app is installed on.
    """
    steps = _dispatch_workflow()["jobs"]["dispatch"]["steps"]
    minted = [
        step for step in steps
        if str(step.get("uses", "")).startswith("actions/create-github-app-token@")
    ]
    assert minted, "the dispatch must be sent as the bot, or release.yml rejects it"
    for step in minted:
        inputs = step.get("with", {})
        assert "owner" not in inputs, inputs
        assert "repositories" not in inputs, inputs


def test_the_initiator_skips_an_already_published_version():
    """A re-merge must not request a release of an immutable tag.

    `release.yml` would refuse it, which is correct but shows up as a failed
    run on an ordinary push.
    """
    script = "\n".join(
        step.get("run", "") for step in _dispatch_workflow()["jobs"]["dispatch"]["steps"]
    )
    assert "isDraft" in script and "already published" in script


def test_the_manual_path_survives_alongside_the_initiator():
    """The owner path is the fallback for when the initiator cannot run."""
    workflow = yaml.load(WORKFLOW_PATH.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"repository_dispatch", "workflow_dispatch"}
    assert "release_reason" in workflow["on"]["workflow_dispatch"]["inputs"]


def test_the_initiator_can_reach_the_bot_credentials():
    """The bot secrets are environment secrets, not repository secrets.

    Without the environment declared, `app-id` resolves to an empty string
    and the token step fails with "must be set to a non-empty string". That
    is how this workflow failed on its first dispatch, and nothing in the
    repository would have caught it: the workflow only runs on a VERSION
    change or a manual dispatch.
    """
    job = _dispatch_workflow()["jobs"]["dispatch"]
    assert job.get("environment") == "scanner-maintenance", (
        "the dispatch job must declare the environment holding "
        "SOURCEBASTION_BOT_APP_ID and SOURCEBASTION_BOT_PRIVATE_KEY"
    )


def hosted_smoke_cleanup() -> str:
    """The shipped cleanup handler, extracted so the test runs the real code."""
    lines = HOSTED_SMOKE_PATH.read_text(encoding="utf-8").splitlines()
    start = lines.index("cleanup() {")
    end = lines.index("}", start)
    body = "\n".join(lines[start : end + 1])
    assert "trap cleanup EXIT" in "\n".join(lines)
    return body


@pytest.mark.parametrize("failing", [False, True])
def test_hosted_smoke_cleanup_survives_read_only_proof_output(tmp_path: Path, failing: bool):
    # The entrypoint proof leaves control/ at 0o555 with a 0o444 record inside,
    # and the release job does not redirect that output outside the temporary
    # directory. A plain `rm -rf` fails there and, from an EXIT trap, turns a
    # fully passing hosted scan into exit 1.
    script = tmp_path / "harness.sh"
    script.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        'work="$(mktemp -d)"\n'
        'echo "$work" > "$1"\n'
        f"{hosted_smoke_cleanup()}\n"
        "trap cleanup EXIT\n"
        'mkdir -m 700 "$work/control"\n'
        ': > "$work/control/job.json"\n'
        'chmod 444 "$work/control/job.json"\n'
        'chmod 555 "$work/control"\n'
        'echo "hosted checks passed"\n'
        '[[ "${FAIL:-}" == 1 ]] && exit 1\n'
        "exit 0\n",
        encoding="utf-8",
    )
    recorded = tmp_path / "work-path"
    environment = dict(os.environ)
    if failing:
        environment["FAIL"] = "1"

    completed = subprocess.run(
        ["bash", str(script), str(recorded)],
        capture_output=True,
        text=True,
        env=environment,
    )

    assert "hosted checks passed" in completed.stdout
    assert "Permission denied" not in completed.stderr
    assert not Path(recorded.read_text(encoding="utf-8").strip()).exists()
    # Cleanup must not change the verdict in either direction.
    assert completed.returncode == (1 if failing else 0)

