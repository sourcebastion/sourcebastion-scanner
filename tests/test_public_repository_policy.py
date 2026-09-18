from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_readme_identifies_the_maintained_upstream_and_support_boundary():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    prose = " ".join(readme.split())

    assert readme.startswith("# SourceBastion Scanner\n")
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
