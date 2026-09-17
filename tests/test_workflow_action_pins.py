"""Supply-chain invariants for executable and customer-shipped workflows."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOTS = (
    ROOT / ".github" / "workflows",
    ROOT / "dashboard" / ".github" / "workflows",
    ROOT / "github" / "dashboard",
    ROOT / "github" / "templates",
)
GENERATORS = (ROOT / "ez_appsec" / "org_manager.py",)
REMOTE_USE = re.compile(
    r"^\s*(?:-\s*)?uses:\s+(?!\./)([^@\s]+)@([^\s#]+)(?:\s+#\s*(\S+))?\s*$"
)
COMMIT = re.compile(r"[0-9a-f]{40}")
VERSION = re.compile(r"v\d+(?:\.\d+){0,2}")


def test_remote_actions_are_pinned_and_consistent():
    """Mutable tags must never execute in our or an adopter's repository."""
    failures: list[str] = []
    observed: dict[tuple[str, str], tuple[str, Path, int]] = {}

    workflow_files = list(GENERATORS)
    for root in WORKFLOW_ROOTS:
        workflow_files.extend((*root.rglob("*.yml"), *root.rglob("*.yaml")))
    for path in sorted(workflow_files):
        for line_number, line in enumerate(path.read_text().splitlines(), 1):
            match = REMOTE_USE.match(line)
            if match is None:
                continue
            action, revision, version = match.groups()
            location = f"{path.relative_to(ROOT)}:{line_number}"
            if COMMIT.fullmatch(revision) is None:
                failures.append(f"{location}: {action}@{revision} is not commit-pinned")
                continue
            if version is None or VERSION.fullmatch(version) is None:
                failures.append(f"{location}: pin needs a human-readable version comment")
                continue
            key = (action, version)
            previous = observed.get(key)
            if previous is not None and previous[0] != revision:
                failures.append(
                    f"{location}: {action} {version} differs from "
                    f"{previous[1].relative_to(ROOT)}:{previous[2]}"
                )
            else:
                observed[key] = (revision, path, line_number)

    assert observed, "no remote GitHub Actions were audited"
    assert not failures, "\n" + "\n".join(failures)
