"""The public scanner command is branded, and the legacy alias is retired."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_sourcebastion_console_script_is_declared():
    """The `ez-appsec` alias assertion is inverted rather than deleted.

    It was kept deliberately, to retain legacy installs. Retiring the name
    means retiring it here too, and the published images have used
    `ENTRYPOINT ["sourcebastion"]` throughout -- so the alias only ever served
    someone who pip-installed the package and typed the old command. Asserting
    its absence keeps that a decision rather than an omission.
    """
    setup = (ROOT / "setup.py").read_text(encoding="utf-8")
    assert '"sourcebastion=sourcebastion.cli:main"' in setup
    assert "ez-appsec" not in setup
    assert 'name="sourcebastion-scanner"' in setup


def test_published_images_use_public_command():
    for name in ("Dockerfile", "Dockerfile.slim", "Dockerfile.thin", "Dockerfile.micro"):
        dockerfile = (ROOT / "images" / name).read_text(encoding="utf-8")
        assert 'ENTRYPOINT ["sourcebastion"]' in dockerfile


def test_dashboard_update_token_targets_the_checked_out_repository():
    import yaml
    workflow = yaml.safe_load((ROOT / ".github/workflows/dashboard-update.yml").read_text())
    steps = workflow["jobs"]["aggregate"]["steps"]
    mint = next(step for step in steps if step.get("id") == "token")["with"]
    checkout = next(step for step in steps if step.get("uses", "").startswith("actions/checkout@"))
    assert "repository" not in checkout["with"]
    assert mint["owner"] == "${{ github.repository_owner }}"
    assert mint["repositories"] == "${{ github.event.repository.name }}"


def test_cli_examples_use_the_installed_command():
    from click.testing import CliRunner
    from sourcebastion.cli import main
    for command in ("serve-metrics", "rotate-secrets"):
        result = CliRunner().invoke(main, [command, "--help"])
        assert result.exit_code == 0
        assert "ez-appsec" not in result.output
