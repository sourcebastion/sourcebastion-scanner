"""Keep the public scanner command branded while retaining legacy installs."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_sourcebastion_console_script_is_declared():
    setup = (ROOT / "setup.py").read_text(encoding="utf-8")
    assert '"sourcebastion=ez_appsec.cli:main"' in setup
    assert '"ez-appsec=ez_appsec.cli:main"' in setup


def test_published_images_use_public_command():
    for name in ("Dockerfile", "Dockerfile.slim", "Dockerfile.thin", "Dockerfile.micro"):
        dockerfile = (ROOT / "images" / name).read_text(encoding="utf-8")
        assert 'ENTRYPOINT ["sourcebastion"]' in dockerfile
