import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def _workflow_trigger(workflow):
    # PyYAML follows YAML 1.1 and parses the unquoted key `on` as True.
    return workflow.get("on", workflow.get(True, {}))


def _pull_request_workflows():
    for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        trigger = _workflow_trigger(workflow)
        if isinstance(trigger, dict) and "pull_request" in trigger:
            yield path, workflow


def _permission_values(permissions):
    if isinstance(permissions, dict):
        return permissions.values()
    return [permissions]


def test_readme_identifies_the_maintained_upstream_and_support_boundary():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    prose = " ".join(readme.split())

    assert readme.startswith("# SourceBastion Scan\n")
    assert "it is not deprecated" in prose
    assert "maintained on a best-effort basis" in prose
    assert "commercial support channel" in prose
    assert "repository will be archived" in prose


def test_contributor_routes_stay_in_the_current_repository():
    documents = [
        (ROOT / "README.md").read_text(encoding="utf-8"),
        (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8"),
        (ROOT / ".github" / "ISSUE_TEMPLATE" / "plan.md").read_text(
            encoding="utf-8"
        ),
        (ROOT / ".github" / "ISSUE_TEMPLATE" / "ai-plan.md").read_text(
            encoding="utf-8"
        ),
    ]

    for document in documents:
        assert "github.com/ez-appsec/ez-appsec" not in document
        assert "github.com/orgs/ez-appsec" not in document


def test_security_policy_uses_the_enabled_private_reporting_route():
    policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")

    assert "sourcebastion/sourcebastion-scanner/security/advisories/new" in policy
    assert "security@ez-appsec.ai" not in policy
    assert "within 48 hours" not in policy
    assert "within 30 days" not in policy
    assert "best-effort basis" in policy


def test_vscode_extension_uses_public_brand_and_maintained_image():
    manifest = json.loads(
        (ROOT / "vscode-extension" / "package.json").read_text(encoding="utf-8")
    )

    assert manifest["name"] == "ez-appsec"  # Stable extension identifier.
    assert manifest["displayName"] == "SourceBastion Scan"
    assert manifest["contributes"]["configuration"]["title"] == "SourceBastion Scan"
    assert (
        manifest["contributes"]["configuration"]["properties"]
        ["ez-appsec.dockerImage"]["default"]
        == "ghcr.io/sourcebastion/sourcebastion-scanner:latest"
    )


def test_pull_request_workflows_use_read_only_tokens_and_safe_checkouts():
    for path, workflow in _pull_request_workflows():
        assert "write" not in _permission_values(workflow.get("permissions", {})), path

        for job_name, job in workflow.get("jobs", {}).items():
            job_permissions = job.get("permissions", {})
            if "write" in _permission_values(job_permissions):
                condition = str(job.get("if", ""))
                assert "github.event_name != 'pull_request'" in condition, (
                    path,
                    job_name,
                )

            for step in job.get("steps", []):
                if str(step.get("uses", "")).startswith("actions/checkout@"):
                    assert step.get("with", {}).get("persist-credentials") is False, (
                        path,
                        job_name,
                    )


def test_pull_request_jobs_do_not_receive_repository_secrets():
    for path, workflow in _pull_request_workflows():
        for job_name, job in workflow.get("jobs", {}).items():
            job_condition = str(job.get("if", ""))
            job_excludes_pr = "github.event_name != 'pull_request'" in job_condition
            for step in job.get("steps", []):
                if "secrets." not in json.dumps(step):
                    continue
                step_condition = str(step.get("if", ""))
                assert job_excludes_pr or "github.event_name != 'pull_request'" in step_condition, (
                    path,
                    job_name,
                    step.get("name"),
                )


def test_pr_writeback_never_checks_out_or_executes_pull_request_source():
    path = ROOT / ".github" / "workflows" / "pr-scan-writeback.yml"
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))

    assert "workflow_run" in _workflow_trigger(workflow)
    serialized = json.dumps(workflow)
    assert "actions/checkout@" not in serialized
    assert '"run"' not in serialized
