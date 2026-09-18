from pathlib import Path
import re

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github" / "workflows" / "security.yml").read_text(
    encoding="utf-8"
)


def test_security_workflow_runs_for_changes_and_on_a_schedule():
    assert "pull_request:" in WORKFLOW
    assert "branches: [main]" in WORKFLOW
    assert "schedule:" in WORKFLOW


def test_dependency_review_is_pull_request_only_and_sha_pinned():
    assert "if: github.event_name == 'pull_request'" in WORKFLOW
    assert re.search(
        r"uses: actions/dependency-review-action@[0-9a-f]{40} # v5\.0\.0",
        WORKFLOW,
    )


def test_codeql_scans_first_party_languages_with_minimal_permissions():
    assert "security-events: write" in WORKFLOW
    assert "language: [python, javascript-typescript]" in WORKFLOW
    assert "build-mode: none" in WORKFLOW
    assert len(
        re.findall(
            r"uses: github/codeql-action/(?:init|analyze)@[0-9a-f]{40} # v4",
            WORKFLOW,
        )
    ) == 2


def test_every_pull_request_can_satisfy_the_required_api_check():
    api_workflow = yaml.load(
        (ROOT / ".github" / "workflows" / "api.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    pull_request = api_workflow["on"]["pull_request"]
    assert pull_request["branches"] == ["main"]
    assert "paths" not in pull_request
