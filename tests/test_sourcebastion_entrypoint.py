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
    for name in ("Dockerfile",):
        dockerfile = (ROOT / "images" / name).read_text(encoding="utf-8")
        assert 'ENTRYPOINT ["sourcebastion"]' in dockerfile


def test_app_tokens_are_scoped_to_the_checked_out_repository():
    """An App token must not be minted for a hardcoded owner.

    This replaces a guard that asserted the same property of
    `dashboard-update.yml`, which went with the retired dashboard. The lesson
    outlives its subject: `create-github-app-token` scopes a token to the
    current repository only when both `owner` and `repositories` are omitted,
    and setting `owner` with an empty `repositories` scopes it to *every*
    repository that owner has installed.
    """
    import yaml

    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/scanner-artifact-update.yml").read_text()
    )
    minted = [
        step
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
        if str(step.get("uses", "")).startswith("actions/create-github-app-token@")
    ]
    assert minted, "no App token step found; this guard has lost its subject"
    for step in minted:
        inputs = step.get("with", {})
        assert "owner" not in inputs, inputs
        assert "repositories" not in inputs, inputs


def test_cli_examples_use_the_installed_command():
    from click.testing import CliRunner
    from sourcebastion.cli import main
    for command in ("serve-metrics", "rotate-secrets"):
        result = CliRunner().invoke(main, [command, "--help"])
        assert result.exit_code == 0
        assert "ez-appsec" not in result.output
