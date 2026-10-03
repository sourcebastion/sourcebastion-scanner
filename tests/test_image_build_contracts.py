"""Static checks for things that only break when an image is actually built.

The image build jobs in `docker.yml` are gated on `inputs.build_images`, which
is set only when `release.yml` calls the workflow. A pull request skips them
entirely, so a defect in a Dockerfile or a build tag is invisible until a
release is dispatched -- which is how a release came to fail twice in a row on
two separate regressions that had been sitting on main.

These assertions are deliberately static: they run in the ordinary test job on
every pull request and cost nothing, so the class of mistake that reached a
release cannot reach one again.
"""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
DOCKERFILES = sorted((ROOT / "images").glob("Dockerfile*"))

# A docker reference's repository name may contain lowercase letters, digits and
# separators only. An uppercase letter is rejected outright by the daemon with
# "repository name must be lowercase", at build time and never before.
TAG_FIELD = re.compile(r"^\s*tags:\s*(?P<value>\S.*)$", re.MULTILINE)
INVALID_REPOSITORY = re.compile(r"[A-Z]")


def _tag_values(text):
    for match in TAG_FIELD.finditer(text):
        value = match.group("value").strip()
        # Multi-line `tags: |` blocks list registry-qualified names built from
        # expressions; those are checked by the registry, not by hand here.
        if value in {"|", ">", "|-", ">-"}:
            continue
        yield value


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_build_tags_are_legal_docker_references(workflow):
    """A literal build tag must be a name the daemon will accept."""
    for value in _tag_values(workflow.read_text(encoding="utf-8")):
        if "${{" in value:  # resolved at run time
            continue
        repository = value.split(":", 1)[0]
        assert not INVALID_REPOSITORY.search(repository), (
            f"{workflow.name}: build tag {value!r} has an uppercase repository "
            "name, which docker rejects as 'repository name must be lowercase'. "
            "This is the shape the rebrand introduced by replacing a lowercase "
            "image name with the brand's capitalisation."
        )


@pytest.mark.parametrize("dockerfile", DOCKERFILES, ids=lambda p: p.name)
def test_ensurepip_stages_do_not_invoke_bare_pip(dockerfile):
    """A stage whose pip comes from `ensurepip` has no plain `pip` on PATH.

    `python3 -m ensurepip` installs `pip3` and `pip3.11`; the unversioned
    console script came from a separate `pip install --upgrade pip`. When that
    line was removed, every `pip ...` in these images became exit 127.
    """
    text = dockerfile.read_text(encoding="utf-8")
    if "ensurepip" not in text:
        pytest.skip("stage does not provision pip through ensurepip")
    offenders = [
        line.strip()
        for line in text.splitlines()
        if re.search(r"(?:^|&&\s*|RUN\s+)pip\s+(?:install|check)\b", line)
    ]
    assert not offenders, (
        f"{dockerfile.name} calls bare `pip` but provisions pip with "
        f"`ensurepip`, which installs no unversioned `pip`: {offenders}. "
        "Use `python3 -m pip`."
    )


# The Dockerfile guard above was not enough on its own: a third `pip` call site
# lived in Python, as an argv list, and reached a release after the Dockerfile
# sites were fixed. A subprocess argv is the same mistake in a different file
# type, so it gets the same check.
SOURCE_DIRS = ("sourcebastion", "scripts")


def _python_files():
    for directory in SOURCE_DIRS:
        yield from sorted((ROOT / directory).rglob("*.py"))


@pytest.mark.parametrize("source", list(_python_files()), ids=lambda p: p.name)
def test_subprocess_argv_does_not_invoke_bare_pip(source):
    """`pip` as argv[0] is not portable; the images have no such binary.

    Unlike npm, go or bundle, pip belongs to the interpreter already running,
    so it is invoked as `sys.executable -m pip`. Bare `pip` raised
    FileNotFoundError inside the scanner images and was reported against
    whichever scanner happened to need it.
    """
    text = source.read_text(encoding="utf-8")
    offenders = [
        line.strip()
        for line in text.splitlines()
        if re.search(r"""\[\s*["']pip["']\s*,""", line)
    ]
    assert not offenders, (
        f"{source.name} invokes bare `pip` as argv[0]: {offenders}. "
        "Use [sys.executable, '-m', 'pip', ...]."
    )


# The third file type. A workflow job that sets `container:` to the scanner
# image runs its steps *inside* that image, so it inherits the image's lack of
# an unversioned `pip` -- and a release that promotes `:latest` breaks such a
# step without anything in this repository changing. That is how the Security
# Scan job started exiting 127 the moment v1.7.34 published.
def _invokes_bare_pip(line: str) -> bool:
    """Whether a shell line runs `pip` as the command itself.

    Tokenised rather than matched with a regex: `python -m pip` and
    `/opt/venv/bin/pip` are both correct -- they name an interpreter or an
    explicit path instead of relying on a console script the image may not
    have -- and distinguishing those from a bare `pip` with lookarounds was
    fiddly enough to get wrong twice.
    """
    tokens = line.replace("&&", " ").replace("|", " ").split()
    for index, token in enumerate(tokens):
        if token != "pip":
            continue  # a path like /opt/venv/bin/pip is explicit, so fine
        if index and tokens[index - 1] == "-m":
            continue  # python -m pip
        if index + 1 < len(tokens) and tokens[index + 1] in {"install", "check"}:
            return True
    return False


def _jobs_running_in_the_scanner_image():
    for workflow in WORKFLOWS:
        document = yaml.safe_load(workflow.read_text(encoding="utf-8")) or {}
        for name, job in (document.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            container = job.get("container")
            image = container.get("image") if isinstance(container, dict) else container
            if isinstance(image, str) and "sourcebastion-scanner" in image:
                yield workflow.name, name, job


def test_steps_inside_the_scanner_image_do_not_invoke_bare_pip():
    """A step running in the scanner image must not assume a `pip` binary."""
    offenders = []
    for workflow_name, job_name, job in _jobs_running_in_the_scanner_image():
        for step in job.get("steps") or []:
            script = step.get("run") if isinstance(step, dict) else None
            if isinstance(script, str):
                offenders += [
                    f"{workflow_name}:{job_name}: {line.strip()}"
                    for line in script.splitlines()
                    if _invokes_bare_pip(line)
                ]
    assert not offenders, (
        "these steps run inside the scanner image, which has no unversioned "
        f"`pip`: {offenders}. Use `python3 -m pip`."
    )


def test_the_guard_actually_finds_jobs_to_check():
    """Guard against the check above silently covering nothing."""
    assert list(_jobs_running_in_the_scanner_image())


# --- the real-execution smoke scan -------------------------------------------

SMOKE_SCRIPT = ROOT / "scripts" / "smoke-scan-juice-shop.sh"


def test_the_standard_image_build_scans_a_real_application():
    """The release path must exercise the scanners for real, not in effigy.

    `verify-scanner-integration.py` checks each binary with `shutil.which` and
    then patches `subprocess.run`, so it proves the parsers work on fixture
    JSON and nothing about whether the scanners run. Two regressions reached
    releases through that gap: grype failing in the `pip` call it makes to
    materialise dependencies, and semgrep discarding an entire scan over one
    unparseable file. Both would have been caught by actually scanning
    something.
    """
    document = yaml.safe_load((ROOT / ".github" / "workflows" / "docker.yml").read_text(encoding="utf-8"))
    steps = document["jobs"]["build-docker-standard"]["steps"]
    scripts = "\n".join(step.get("run", "") for step in steps if isinstance(step, dict))
    assert "smoke-scan-juice-shop.sh" in scripts, (
        "the standard image build no longer runs the real-execution smoke scan"
    )


def test_the_smoke_scan_pins_its_corpus():
    """A release must not fail because an upstream repository changed today."""
    text = SMOKE_SCRIPT.read_text(encoding="utf-8")
    pin = re.search(r'corpus_sha="([0-9a-f]{40})"', text)
    assert pin, "the smoke corpus must be pinned to a full commit sha"


def test_the_smoke_scan_asserts_each_scanner_separately():
    """A total-count assertion would pass with one scanner doing all the work.

    grype alone produced every finding on the fixture corpus while gitleaks,
    semgrep and kics produced none, so a bare `findings > 0` check is not
    evidence that the scanners work.
    """
    text = SMOKE_SCRIPT.read_text(encoding="utf-8")
    expected = re.search(r'expected_scanners="([^"]+)"', text)
    assert expected, "the smoke scan must name the scanners it requires"
    assert set(expected.group(1).split()) >= {"semgrep", "gitleaks", "grype"}


def test_the_standard_image_build_runs_the_iac_component_for_real():
    """IaC needs its own real-execution check; the smoke corpus cannot cover it.

    Juice Shop carries no infrastructure code, so `kics` is deliberately absent
    from the smoke scan's required scanners -- which is exactly how KICS came
    to discard every finding for every repository across several releases
    without anything noticing.
    """
    document = yaml.safe_load((ROOT / ".github" / "workflows" / "docker.yml").read_text(encoding="utf-8"))
    steps = document["jobs"]["build-docker-standard"]["steps"]
    scripts = "\n".join(step.get("run", "") for step in steps if isinstance(step, dict))
    assert "smoke-scan-iac.sh" in scripts, (
        "the standard image build no longer runs the IaC component for real"
    )


def test_the_iac_check_requires_a_finding_rather_than_a_clean_run():
    """Exit zero on an empty result would assert nothing.

    The fixture contains an unrestricted security group, so zero findings means
    the wrapper is discarding output -- the check must fail, not pass quietly.
    """
    text = (ROOT / "scripts" / "smoke-scan-iac.sh").read_text(encoding="utf-8")
    assert "if not findings:" in text
    assert "sys.exit(" in text
