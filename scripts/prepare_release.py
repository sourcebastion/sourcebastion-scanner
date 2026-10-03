"""Create a reviewed release version and changelog; never publish images."""
from datetime import date
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def prepare(version, notes):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("release version must be MAJOR.MINOR.PATCH")
    previous = (ROOT / "VERSION").read_text().strip()
    if tuple(map(int, version.split("."))) <= tuple(map(int, previous.split("."))):
        raise ValueError("release version must increase")
    if len(notes.strip()) < 12 or re.search(r"^## ", notes, re.MULTILINE):
        raise ValueError("release notes must describe the changes and contain no version headings")
    changelog_path = ROOT / "CHANGELOG.md"
    changelog = changelog_path.read_text()
    first_release = re.search(r"^## \[?[0-9]", changelog, re.MULTILINE)
    if first_release is None:
        raise ValueError("changelog has no version sections")
    entry = f"## [{version}] - {date.today().isoformat()}\n\n{notes.strip()}\n\n"
    changelog_path.write_text(changelog[:first_release.start()] + entry + changelog[first_release.start():])
    (ROOT / "VERSION").write_text(version + "\n")


if __name__ == "__main__":
    prepare(os.environ["RELEASE_VERSION"], os.environ["RELEASE_NOTES"])
