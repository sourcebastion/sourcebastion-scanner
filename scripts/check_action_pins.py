#!/usr/bin/env python3
"""Verify every pinned GitHub Action against its documented upstream tag."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOTS = (
    ROOT / ".github" / "workflows",
    ROOT / "dashboard" / ".github" / "workflows",
    ROOT / "github" / "dashboard",
    ROOT / "github" / "templates",
)
GENERATORS = (ROOT / "ez_appsec" / "org_manager.py",)
REMOTE_USE = re.compile(
    r"^\s*(?:-\s*)?uses:\s+(?!\./)([^@\s]+)@([0-9a-f]{40})\s+#\s*(v\d+(?:\.\d+){0,2})\s*$"
)


@dataclass(frozen=True)
class Pin:
    action: str
    revision: str
    version: str
    path: Path
    line: int


def discover_pins() -> list[Pin]:
    files = list(GENERATORS)
    for root in WORKFLOW_ROOTS:
        files.extend((*root.rglob("*.yml"), *root.rglob("*.yaml")))

    pins = []
    for path in sorted(set(files)):
        for line_number, line in enumerate(path.read_text().splitlines(), 1):
            match = REMOTE_USE.match(line)
            if match:
                pins.append(Pin(*match.groups(), path, line_number))
    return pins


class GitHubAPI:
    def __init__(self, token: str = "") -> None:
        self.token = token

    def get(self, path: str) -> dict:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "sourcebastion-action-pin-audit",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(
            f"https://api.github.com{path}", headers=headers
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.load(response)

    def resolve_tag(self, action: str, version: str) -> str:
        repository = "/".join(action.split("/")[:2])
        current = self.get(f"/repos/{repository}/git/ref/tags/{version}")[
            "object"
        ]
        for _ in range(4):
            if current["type"] == "commit":
                return current["sha"]
            if current["type"] != "tag":
                raise ValueError(f"unexpected git object type {current['type']!r}")
            current = self.get(
                f"/repos/{repository}/git/tags/{current['sha']}"
            )["object"]
        raise ValueError("annotated tag chain is too deep")


def audit(api: GitHubAPI) -> list[str]:
    failures = []
    pins = discover_pins()
    expected: dict[tuple[str, str], str] = {}
    for pin in pins:
        key = (pin.action, pin.version)
        try:
            if key not in expected:
                expected[key] = api.resolve_tag(*key)
            upstream = expected[key]
        except (KeyError, ValueError, urllib.error.HTTPError, urllib.error.URLError) as exc:
            failures.append(f"{pin.action}@{pin.version}: lookup failed: {exc}")
            continue
        if pin.revision != upstream:
            location = f"{pin.path.relative_to(ROOT)}:{pin.line}"
            failures.append(
                f"{location}: {pin.action}@{pin.version} is {pin.revision}; "
                f"upstream tag resolves to {upstream}"
            )
    if not pins:
        failures.append("no pinned Actions found")
    return failures


def main() -> int:
    failures = audit(GitHubAPI(os.environ.get("GITHUB_TOKEN", "")))
    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        print("See docs/action-pin-maintenance.md before changing a pin.")
        return 1
    print(f"Verified {len(discover_pins())} Action references against upstream tags.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
