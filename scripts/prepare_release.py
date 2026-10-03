"""Create a reviewed release version and changelog; never publish images."""
import argparse
from datetime import date
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def resolve_version(requested="auto"):
    previous = (ROOT / "VERSION").read_text().strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", previous):
        raise ValueError("VERSION must be MAJOR.MINOR.PATCH")
    requested = requested.strip()
    if not requested or requested == "auto":
        major, minor, patch = map(int, previous.split("."))
        version = f"{major}.{minor}.{patch + 1}"
    else:
        version = requested
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("release version must be MAJOR.MINOR.PATCH")
    if tuple(map(int, version.split("."))) <= tuple(map(int, previous.split("."))):
        raise ValueError("release version must increase")
    return version


def prepare(version, notes):
    version = resolve_version(version)
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resolve-version")
    parser.add_argument("--notes-file", type=Path)
    args = parser.parse_args()
    if args.resolve_version is not None:
        print(resolve_version(args.resolve_version))
    else:
        notes = os.environ.get("RELEASE_NOTES", "")
        if not notes.strip() and args.notes_file:
            notes = re.sub(r"^## ", "### ", args.notes_file.read_text(), flags=re.MULTILINE)
        prepare(os.environ.get("RELEASE_VERSION", "auto"), notes)
