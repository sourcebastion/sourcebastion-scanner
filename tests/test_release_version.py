"""The version a build reports must be the version being released.

Every release through v1.7.34 shipped distribution metadata saying `0.1.0`,
because `setup.py` carried a literal that nobody updated. `--version` inside a
digest-pinned contract scanner could not say which release it was, which is
precisely when you need it: the image is identified by a digest, so its own
self-report is the only human-readable handle.

The cause was a second copy of a fact. `VERSION` already is the authority --
`release.yml` refuses to publish unless the dispatched tag equals
`v$(cat VERSION)` -- so these tests exist to keep the number derived from it
rather than restated beside it.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SETUP = ROOT / "setup.py"
VERSION_FILE = ROOT / "VERSION"


def _declared_version() -> str:
    return VERSION_FILE.read_text(encoding="utf-8").strip()


def _setup_py_version(**env) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SETUP), "--version"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={**os.environ, **env},
    )


def test_version_file_is_an_exact_release_version():
    assert re.fullmatch(r"\d+\.\d+\.\d+", _declared_version())


def test_packaging_metadata_reports_the_declared_version():
    """The built distribution must carry VERSION, not a placeholder."""
    completed = _setup_py_version()
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip().splitlines()[-1] == _declared_version()


def test_setup_py_does_not_restate_the_version():
    """A literal here is the second copy that drifted. Keep it derived."""
    text = SETUP.read_text(encoding="utf-8")
    literals = re.findall(r"""version\s*=\s*["']\d+\.\d+\.\d+["']""", text)
    assert not literals, (
        f"setup.py hardcodes a version {literals}. Derive it from VERSION, "
        "which release.yml already validates against the dispatched tag."
    )


def test_an_explicit_override_wins_for_non_release_builds():
    completed = _setup_py_version(SOURCEBASTION_VERSION="9.9.9")
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip().splitlines()[-1] == "9.9.9"


def test_a_malformed_version_fails_the_build():
    """Never fall back to a placeholder: that is how 0.1.0 shipped."""
    completed = _setup_py_version(SOURCEBASTION_VERSION="not-a-version")
    assert completed.returncode != 0
    assert "MAJOR.MINOR.PATCH" in completed.stderr + completed.stdout


def test_the_cli_resolves_its_version_from_the_installed_distribution():
    """`--version` must read metadata, so fixing packaging fixes the CLI.

    Pinned because the package is `sourcebastion` while the distribution is
    `sourcebastion-scanner`; without the explicit name click raises
    "'sourcebastion' is not installed".
    """
    cli = (ROOT / "sourcebastion" / "cli.py").read_text(encoding="utf-8")
    assert 'click.version_option(package_name="sourcebastion-scanner")' in cli
