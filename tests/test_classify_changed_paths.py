"""The gate that decides whether the native image proofs run.

A wrong `false` here silently stops the only jobs that exercise the installed
image, so these tests care most about the directions that could do that.
"""

import importlib.util
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[1] / "scripts/classify-changed-paths.py"
_SPEC = importlib.util.spec_from_file_location("classify_changed_paths", _PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
image_affecting = _MODULE.image_affecting


def test_a_commit_touching_both_docs_and_code_still_builds():
    """The case that must never regress: one inert path alongside real code
    does not buy a skip."""
    assert image_affecting(["docs/M046-S04-acceptance.md", "sourcebastion/inventory/contract.py"])
    assert image_affecting(["sourcebastion/inventory/contract.py", "docs/M046-S04-acceptance.md"])


@pytest.mark.parametrize(
    "paths",
    [
        ["docs/a.md"],
        ["docs/a.md", "docs/nested/b.md"],
        [".github/ISSUE_TEMPLATE/bug.yml"],
        ["docs/a.md", ".github/ISSUE_TEMPLATE/bug.yml"],
    ],
)
def test_only_inert_paths_skip_the_build(paths):
    assert not image_affecting(paths)


@pytest.mark.parametrize(
    "path",
    [
        "sourcebastion/inventory/imported_sbom.py",
        # setup.py reads README.md for long_description, so markdown really
        # does feed packaging metadata.
        "README.md",
        "ROADMAP.md",
        # The verify scripts run against the built image.
        "scripts/verify-inventory-entrypoint.py",
        # Rules ship in the image.
        "rules/foo/rule.yaml",
        # A markdown file under a directory the image copies.
        "rules/foo/README.md",
        # Pinned schemas and fixtures the proofs read.
        "evaluation/m046/pins.json",
        "images/Dockerfile",
        ".dockerignore",
        # A workflow change must re-run itself.
        ".github/workflows/docker.yml",
        "setup.py",
        "pyproject.toml",
        "requirements.txt",
        "tests/test_inventory_contract.py",
    ],
)
def test_anything_else_builds(path):
    assert image_affecting([path])


@pytest.mark.parametrize("paths", [[], [""], ["   ", ""]])
def test_an_unresolvable_diff_builds(paths):
    """No resolvable diff is not evidence that nothing changed."""
    assert image_affecting(paths)


def test_a_path_merely_starting_with_a_doc_name_is_not_inert():
    """`docs/` is a directory prefix, not a substring match."""
    assert image_affecting(["docsrc/thing.py"])
    assert image_affecting(["documentation.py"])
    assert image_affecting(["sourcebastion/docs/__init__.py"])
