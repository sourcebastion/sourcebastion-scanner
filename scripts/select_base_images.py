"""Choose upstream or mirrored base image references for one build.

Emits GitHub Actions outputs. The mirror is preferred because buildkit
resolves a base manifest from the registry on every build, and anonymous
Docker Hub quota is per client address and shared across GitHub-hosted
runners. Upstream is the fallback, so a pin bump -- whose digest the mirror
has not copied yet -- still builds instead of failing closed on a registry
that is merely an optimization.

The chosen reference is always digest-pinned, and the digest is the same in
either registry, so the fallback cannot change which bytes are built.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from base_image_mirror import build_args, dockerfile_agrees, pins  # noqa: E402

TIMEOUT = 20


def anonymous_token(host, path):
    """A pull token for a public package, obtained without credentials.

    Deliberately unauthenticated: this runs in pull request builds, and a
    public repository must not hand repository secrets to one. A mirror that
    is not publicly readable therefore reads as unavailable, and the build
    falls back to upstream rather than failing.
    """
    query = urllib.parse.urlencode({"service": host, "scope": f"repository:{path}:pull"})
    try:
        with urllib.request.urlopen(f"https://{host}/token?{query}", timeout=TIMEOUT) as response:
            return json.load(response).get("token") or ""
    except (urllib.error.URLError, OSError, ValueError):
        return ""


def serves(image):
    """True when the mirror can return the exact pinned manifest."""
    repository = image["mirror_repository"]
    host, path = repository.split("/", 1)
    token = anonymous_token(host, path)
    url = f"https://{host}/v2/{path}/manifests/{image['digest']}"
    request = urllib.request.Request(url, method="HEAD")
    request.add_header(
        "Accept",
        "application/vnd.oci.image.index.v1+json,"
        "application/vnd.docker.distribution.manifest.list.v2+json,"
        "application/vnd.oci.image.manifest.v1+json,"
        "application/vnd.docker.distribution.manifest.v2+json",
    )
    if token:
        request.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError, ValueError):
        # Any doubt means upstream. A mirror that cannot be confirmed is not
        # a mirror this build should depend on.
        return False


def main():
    images = pins()
    dockerfile_agrees(images)
    mirrored = all(serves(image) for image in images)
    chosen = build_args(images, mirrored=mirrored)
    inline = " ".join(f'--build-arg "{name}={value}"' for name, value in sorted(chosen.items()))
    lines = "\n".join(f"{name}={value}" for name, value in sorted(chosen.items()))
    print("source=" + ("mirror" if mirrored else "upstream"))
    print("build_args=" + inline)
    print("build_args_multiline<<SOURCEBASTION_EOF")
    print(lines)
    print("SOURCEBASTION_EOF")
    # Visible in the log so a reviewer can see which registry served a build.
    print(f"::notice::base images resolved from {'the mirror' if mirrored else 'upstream'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
