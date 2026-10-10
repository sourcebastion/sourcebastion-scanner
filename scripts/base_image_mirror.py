"""Base image pins and the mirror that serves them.

The scanner image builds from two upstream images on Docker Hub. Anonymous
Hub pulls are rate limited per client address, GitHub-hosted runners share
addresses with every other Actions user, and buildkit resolves a base image
manifest from the registry on every build even on a complete layer-cache hit.
So builds fail for reasons that have nothing to do with the change under test.

`.github/base-image-pins.json` records the upstream digest, which stays
authoritative. The mirror is a byte-identical copy in a registry this
organization controls, so a pinned digest denotes the same bytes in either
place and the pin keeps meaning exactly what it meant before.

Nothing here pulls, builds or pushes. It reads the pins, states the references
and checks agreement; a workflow performs the copy.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PINS = ROOT / ".github/base-image-pins.json"
DOCKERFILE = ROOT / "images/Dockerfile"
SCHEMA = "sourcebastion.base-image-pins/1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPOSITORY = re.compile(r"^[a-z0-9.\-]+(?::[0-9]+)?/[a-z0-9._\-/]+$")


class PinError(ValueError):
    """The pins are malformed or disagree with the Dockerfile."""


def pins(path=PINS):
    value = json.loads(path.read_text())
    if value.get("schema_version") != SCHEMA:
        raise PinError("base-image-pins-schema-invalid")
    images = value.get("images")
    if type(images) is not list or not images:
        raise PinError("base-image-pins-empty")
    names = set()
    for image in images:
        for field in ("name", "upstream_repository", "digest", "mirror_repository"):
            if type(image.get(field)) is not str or not image[field]:
                raise PinError("base-image-pin-field-missing")
        if image["name"] in names:
            raise PinError("base-image-pin-duplicate")
        names.add(image["name"])
        if _DIGEST.fullmatch(image["digest"]) is None:
            raise PinError("base-image-pin-digest-invalid")
        for field in ("upstream_repository", "mirror_repository"):
            if _REPOSITORY.fullmatch(image[field]) is None:
                raise PinError("base-image-pin-repository-invalid")
        # A mirror that could serve a different repository's bytes under the
        # same digest would defeat the point of pinning.
        if image["mirror_repository"] == image["upstream_repository"]:
            raise PinError("base-image-mirror-must-differ")
    return images


def reference(image, *, mirrored):
    """The fully qualified, always digest-pinned reference to build from."""
    repository = image["mirror_repository"] if mirrored else image["upstream_repository"]
    return f"{repository}@{image['digest']}"


def build_args(images, *, mirrored):
    """Docker build arguments naming each base image, by digest."""
    return {f"{image['name'].upper()}_BASE": reference(image, mirrored=mirrored) for image in images}


def dockerfile_agrees(images, path=DOCKERFILE):
    """Every pin must be the Dockerfile's default, so a plain `docker build`
    and a mirrored CI build resolve the same bytes."""
    text = path.read_text()
    for image in images:
        expected = f"ARG {image['name'].upper()}_BASE={reference(image, mirrored=False)}"
        if expected not in text:
            raise PinError("dockerfile-base-image-pin-mismatch:" + image["name"])
    return True


def main():
    images = pins()
    dockerfile_agrees(images)
    print(json.dumps({
        "upstream": build_args(images, mirrored=False),
        "mirrored": build_args(images, mirrored=True),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
