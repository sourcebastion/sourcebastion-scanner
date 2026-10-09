"""Decide whether a set of changed paths can affect the scanner image.

Separate from the workflow so the decision is testable. Inline shell in YAML
is not, and this decision gates the native proofs that catch packaging
regressions.

The rule is a denylist on purpose: a change is image-affecting unless *every*
changed path is inert. An allowlist of source paths would fail open -- add a
directory, forget to list it, and the native proofs silently stop running. A
missing inert pattern only costs an unnecessary build.

Reads newline-separated paths on stdin. Prints `true` or `false`.
"""

import sys

#: Paths that provably cannot reach the image. `docs/` is in .dockerignore, so
#: it is excluded from the build context outright.
#:
#: Deliberately absent: root markdown, because setup.py reads README.md for
#: long_description, so markdown feeds packaging metadata; `scripts/`, because
#: the verify scripts run against the built image; `rules/`, because they ship
#: in it; `evaluation/`, which holds the pinned schemas and fixtures the proofs
#: read; and `.github/workflows/`, because a workflow change must re-run itself.
INERT_PREFIXES = ("docs/", ".github/ISSUE_TEMPLATE/")


def image_affecting(paths):
    """True unless every supplied path is inert. Empty input is affecting."""
    considered = [path.strip() for path in paths if path.strip()]
    if not considered:
        # No resolvable diff is not evidence that nothing changed.
        return True
    return not all(path.startswith(INERT_PREFIXES) for path in considered)


def main():
    print("true" if image_affecting(sys.stdin.read().splitlines()) else "false")


if __name__ == "__main__":
    main()
