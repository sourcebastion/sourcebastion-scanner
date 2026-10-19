"""The old operator command must explain migration without provider access."""

from click.testing import CliRunner
from sourcebastion.cli import main


def test_org_sync_explains_platform_migration(monkeypatch):
    import urllib.request

    def unexpected_request(*args, **kwargs):
        raise AssertionError("scanner must not contact provider")

    monkeypatch.setattr(urllib.request, "urlopen", unexpected_request)
    result = CliRunner().invoke(main, ["org-sync", "--org", "example", "--dry-run"],
                                env={"GITHUB_TOKEN": "unused-test-token"})
    assert result.exit_code != 0
    assert "sourcebastion-org-sync" in result.output
    assert "sourcebastion-platform" in result.output
