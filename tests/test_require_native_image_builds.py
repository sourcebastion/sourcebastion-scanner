"""The required check behind the native image proofs.

It must stay fail-closed: a skipped build is acceptable only when the path
classifier succeeded and said the change cannot affect the image. Everything
else refuses, because this gate is the only thing between a merge and the jobs
that exercise the installed image.
"""

import subprocess
from pathlib import Path

import pytest

GATE = Path(__file__).resolve().parents[1] / "scripts/require-native-image-builds.sh"


def gate(**environment):
    return subprocess.run(
        ["bash", str(GATE)],
        env={"PATH": "/usr/bin:/bin", **environment},
        capture_output=True,
        text=True,
    )


def test_successful_native_builds_pass():
    result = gate(BUILD_RESULT="success", CHANGES_RESULT="success", IMAGE_AFFECTING="true")
    assert result.returncode == 0
    assert "succeeded" in result.stdout


def test_a_documentation_only_skip_passes():
    result = gate(BUILD_RESULT="skipped", CHANGES_RESULT="success", IMAGE_AFFECTING="false")
    assert result.returncode == 0
    assert "correctly skipped" in result.stdout


def test_a_skip_on_an_image_affecting_change_refuses():
    """The regression that would matter: builds skipped when they were needed."""
    result = gate(BUILD_RESULT="skipped", CHANGES_RESULT="success", IMAGE_AFFECTING="true")
    assert result.returncode == 1


@pytest.mark.parametrize("changes", ["failure", "cancelled", "skipped", ""])
def test_a_skip_without_a_trustworthy_classifier_refuses(changes):
    """`image_affecting` is only meaningful if the classifier actually ran."""
    result = gate(BUILD_RESULT="skipped", CHANGES_RESULT=changes, IMAGE_AFFECTING="false")
    assert result.returncode == 1


@pytest.mark.parametrize("build", ["failure", "cancelled", ""])
def test_a_build_that_did_not_succeed_refuses(build):
    result = gate(BUILD_RESULT=build, CHANGES_RESULT="success", IMAGE_AFFECTING="false")
    assert result.returncode == 1


@pytest.mark.parametrize("affecting", ["true", "", "FALSE", "no", "0"])
def test_only_the_exact_false_signal_excuses_a_skip(affecting):
    """No truthiness games: anything but a literal `false` refuses."""
    result = gate(BUILD_RESULT="skipped", CHANGES_RESULT="success", IMAGE_AFFECTING=affecting)
    assert result.returncode == 1


def test_an_entirely_unset_environment_refuses():
    result = gate()
    assert result.returncode == 1
    assert "unset" in result.stdout


def test_the_refusal_names_what_it_saw():
    result = gate(BUILD_RESULT="skipped", CHANGES_RESULT="failure", IMAGE_AFFECTING="false")
    assert result.returncode == 1
    for fragment in ("build: skipped", "classifier: failure", "image_affecting: false"):
        assert fragment in result.stdout, fragment
