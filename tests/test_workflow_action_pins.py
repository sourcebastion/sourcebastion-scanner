"""Supply-chain invariants for executable and customer-shipped workflows."""

from pathlib import Path
import re

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOTS = (
    ROOT / ".github" / "workflows",
    ROOT / "dashboard" / ".github" / "workflows",
    ROOT / "github" / "dashboard",
    ROOT / "github" / "templates",
)
GENERATORS = (ROOT / "ez_appsec" / "org_manager.py",)
REMOTE_USE = re.compile(
    r"^\s*(?:-\s*)?uses:\s+(?!\./)([^@\s]+)@([^\s#]+)(?:\s+#\s*(\S+))?\s*$"
)
COMMIT = re.compile(r"[0-9a-f]{40}")
VERSION = re.compile(r"v\d+(?:\.\d+){0,2}")


def test_remote_actions_are_pinned_and_consistent():
    """Mutable tags must never execute in our or an adopter's repository."""
    failures: list[str] = []
    observed: dict[tuple[str, str], tuple[str, Path, int]] = {}

    workflow_files = list(GENERATORS)
    for root in WORKFLOW_ROOTS:
        workflow_files.extend((*root.rglob("*.yml"), *root.rglob("*.yaml")))
    for path in sorted(workflow_files):
        for line_number, line in enumerate(path.read_text().splitlines(), 1):
            match = REMOTE_USE.match(line)
            if match is None:
                continue
            action, revision, version = match.groups()
            location = f"{path.relative_to(ROOT)}:{line_number}"
            if COMMIT.fullmatch(revision) is None:
                failures.append(f"{location}: {action}@{revision} is not commit-pinned")
                continue
            if version is None or VERSION.fullmatch(version) is None:
                failures.append(f"{location}: pin needs a human-readable version comment")
                continue
            key = (action, version)
            previous = observed.get(key)
            if previous is not None and previous[0] != revision:
                failures.append(
                    f"{location}: {action} {version} differs from "
                    f"{previous[1].relative_to(ROOT)}:{previous[2]}"
                )
            else:
                observed[key] = (revision, path, line_number)

    assert observed, "no remote GitHub Actions were audited"
    assert not failures, "\n" + "\n".join(failures)


def test_release_paths_have_two_codeowners():
    entries = {}
    for line in (ROOT / ".github" / "CODEOWNERS").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        path, *owners = line.split()
        entries[path] = owners

    for path in (
        "/.github/CODEOWNERS",
        "/.github/workflows/",
        "/.github/dependabot.yml",
        "/.releaserc.json",
        "/package.json",
        "/package-lock.json",
        "/Dockerfile.api",
        "/images/",
    ):
        assert entries[path] == ["@jfelten", "@jenfelten"]


def test_docker_quality_actions_receive_supported_inputs():
    workflow = yaml.load(
        (ROOT / ".github" / "workflows" / "docker.yml").read_text(
            encoding="utf-8"
        ),
        Loader=yaml.BaseLoader,
    )

    lint_steps = workflow["jobs"]["lint-docker"]["steps"]
    hadolint_steps = [
        step
        for step in lint_steps
        if step.get("uses", "").startswith("hadolint/hadolint-action@")
    ]
    assert [step["with"]["dockerfile"] for step in hadolint_steps] == [
        "images/Dockerfile",
        "images/Dockerfile.slim",
        "images/Dockerfile.micro",
        "images/Dockerfile.semgrep",
    ]
    assert all(
        step["with"]["failure-threshold"] == "error" for step in hadolint_steps
    )
    assert all("continue-on-error" not in step for step in hadolint_steps)

    unit_steps = workflow["jobs"]["test-unit"]["steps"]
    codecov_step = next(
        step
        for step in unit_steps
        if step.get("uses", "").startswith("codecov/codecov-action@")
    )
    assert codecov_step["with"]["files"] == "./coverage.xml"
    assert "file" not in codecov_step["with"]
