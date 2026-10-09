"""Pinned base images and the mirror that serves them.

The mirror exists so builds stop depending on anonymous Docker Hub quota. It
is only safe because a pinned digest denotes the same bytes in either
registry, so these tests care most about that equivalence and about the
Dockerfile default never drifting from the pins.
"""

import importlib.util
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mirror = _module("base_image_mirror")


def test_the_shipped_pins_are_well_formed_and_match_the_dockerfile():
    """A plain `docker build` and a mirrored CI build must resolve the same
    bytes, which only holds while the Dockerfile default is the pin."""
    images = mirror.pins()

    assert {image["name"] for image in images} == {"python", "kics"}
    assert mirror.dockerfile_agrees(images) is True


def test_every_chosen_reference_is_digest_pinned_in_both_registries():
    images = mirror.pins()

    for mirrored in (False, True):
        for image in images:
            reference = mirror.reference(image, mirrored=mirrored)
            assert "@sha256:" in reference, reference
            assert reference.endswith(image["digest"])


def test_the_fallback_cannot_change_which_bytes_are_built():
    """Upstream and mirror differ only in the registry, never in the digest,
    so falling back to upstream builds the same image."""
    images = mirror.pins()

    for image in images:
        upstream = mirror.reference(image, mirrored=False)
        mirrored = mirror.reference(image, mirrored=True)
        assert upstream != mirrored
        assert upstream.split("@", 1)[1] == mirrored.split("@", 1)[1]


def write(tmp_path, document):
    path = tmp_path / "pins.json"
    path.write_text(json.dumps(document))
    return path


def document(**changes):
    value = json.loads((ROOT / ".github/base-image-pins.json").read_text())
    value.update(changes)
    return value


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"schema_version": "other/1"}, "schema-invalid"),
        ({"images": []}, "empty"),
        ({"images": "python"}, "empty"),
    ],
)
def test_a_malformed_pins_document_is_refused(tmp_path, changes, reason):
    with pytest.raises(mirror.PinError, match=reason):
        mirror.pins(write(tmp_path, document(**changes)))


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (lambda i: i.update(digest="sha256:nothex"), "digest-invalid"),
        (lambda i: i.update(digest="e" * 64), "digest-invalid"),
        (lambda i: i.pop("mirror_repository"), "field-missing"),
        (lambda i: i.update(upstream_repository="python"), "repository-invalid"),
        (lambda i: i.update(mirror_repository=i["upstream_repository"]), "must-differ"),
    ],
)
def test_an_unusable_pin_is_refused(tmp_path, mutate, reason):
    value = document()
    mutate(value["images"][0])

    with pytest.raises(mirror.PinError, match=reason):
        mirror.pins(write(tmp_path, value))


def test_two_pins_with_one_name_are_refused(tmp_path):
    value = document()
    value["images"].append(dict(value["images"][0]))

    with pytest.raises(mirror.PinError, match="duplicate"):
        mirror.pins(write(tmp_path, value))


def test_a_dockerfile_that_drifted_from_the_pins_is_refused(tmp_path):
    """The failure this guards: CI silently building a different base image
    from the one a local build and the pins name."""
    drifted = tmp_path / "Dockerfile"
    drifted.write_text("ARG PYTHON_BASE=docker.io/library/python@sha256:" + "a" * 64 + "\n")

    with pytest.raises(mirror.PinError, match="dockerfile-base-image-pin-mismatch:python"):
        mirror.dockerfile_agrees(mirror.pins(), drifted)


def workflow(name):
    # BaseLoader keeps `on` a string key; YAML 1.1 would read it as boolean.
    return yaml.load((ROOT / ".github/workflows" / name).read_text(), Loader=yaml.BaseLoader)


def triggers(document):
    on = document["on"]
    return set(on) if isinstance(on, dict) else {on} if isinstance(on, str) else set(on)


def test_the_mirror_never_runs_on_a_pull_request():
    """It pushes packages, so it must not execute an untrusted branch."""
    document = workflow("base-image-mirror.yml")

    assert "pull_request" not in triggers(document)
    assert "pull_request_target" not in triggers(document)
    assert triggers(document) == {"schedule", "workflow_dispatch", "push"}
    assert document["on"]["push"]["branches"] == ["main"]


def test_the_mirror_requests_package_write_only_where_it_pushes():
    document = workflow("base-image-mirror.yml")

    assert document["permissions"] == {"contents": "read"}
    assert document["jobs"]["mirror"]["permissions"] == {"contents": "read", "packages": "write"}
    # Any other job gaining package write would be a new publishing surface.
    assert set(document["jobs"]) == {"mirror"}


def test_the_mirror_copies_a_digest_pinned_source_with_a_pinned_tool():
    text = (ROOT / ".github/workflows/base-image-mirror.yml").read_text()

    assert "gcr.io/go-containerregistry/crane@sha256:" in text, "the copy tool must be pinned"
    assert "crane copy" in text and "crane manifest" in text, "copy, then confirm the digest resolves"


def test_the_build_asks_for_a_selection_before_building():
    """Without this the build would use the Dockerfile default and the mirror
    would never be consulted."""
    document = workflow("docker.yml")
    steps = document["jobs"]["build-scanner"]["steps"]
    names = [step.get("name") for step in steps]

    assert "Select base image references" in names
    assert names.index("Select base image references") < names.index("Build scanner image with retries")
    build = next(step for step in steps if step.get("name") == "Build scanner image with retries")
    assert "steps.bases.outputs.build_args_multiline" in build["with"]["build-args"]
