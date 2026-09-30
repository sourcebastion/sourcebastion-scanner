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
