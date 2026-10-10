"""Resolve and verify the official native Python bases during release preparation."""

import hashlib
import json
import re
from urllib.request import Request, urlopen

MAX_METADATA = 2 * 1024**2
ACCEPT = ",".join((
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
))


def fetch(url, *, token=None):
    headers = {"Accept": ACCEPT}
    if token:
        headers["Authorization"] = "Bearer " + token
    with urlopen(Request(url, headers=headers), timeout=60) as response:
        raw = response.read(MAX_METADATA + 1)
    if not raw or len(raw) > MAX_METADATA:
        raise ValueError("python-base-metadata-bound")
    return raw


def resolve(version, alpine):
    """Bind both native manifests and their configs before changing any pin."""
    if not re.fullmatch(r"3\.[0-9]+\.[0-9]+", version) or not re.fullmatch(r"[0-9]+\.[0-9]+", alpine):
        raise ValueError("python-base-version-invalid")
    token = json.loads(fetch("https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/python:pull"))["token"]
    endpoint = "https://registry-1.docker.io/v2/library/python/"
    tag = f"{version}-alpine{alpine}"
    raw = fetch(endpoint + "manifests/" + tag, token=token)
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    index = json.loads(raw)

    def verified(descriptor, kind):
        identity = descriptor["digest"]
        if not isinstance(identity, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", identity):
            raise ValueError("python-base-digest-invalid")
        content = fetch(endpoint + kind + "/" + identity, token=token)
        if (type(descriptor["size"]) is not int or len(content) != descriptor["size"]
                or "sha256:" + hashlib.sha256(content).hexdigest() != identity):
            raise ValueError("python-base-descriptor-mismatch")
        return json.loads(content)

    native = {}
    for architecture in ("amd64", "arm64"):
        rows = [row for row in index["manifests"] if row.get("platform", {}).get("os") == "linux"
                and row["platform"].get("architecture") == architecture
                and row["platform"].get("variant", "") in ({"", "v8"} if architecture == "arm64" else {""})]
        if len(rows) != 1:
            raise ValueError("python-base-native-manifest-required:" + architecture)
        manifest = verified(rows[0], "manifests")
        config = verified(manifest["config"], "blobs")
        if (config.get("os") != "linux" or config.get("architecture") != architecture
                or [entry for entry in config.get("config", {}).get("Env", []) if entry.startswith("PYTHON_VERSION=")]
                != ["PYTHON_VERSION=" + version]):
            raise ValueError("python-base-native-config-mismatch:" + architecture)
        native[architecture] = rows[0]["digest"]
    return tag, digest, native


def updated_files(root, version):
    """Prepare the coupled pin updates in memory; the caller owns publication."""
    base_path = root / ".github/base-image-pins.json"
    runtime_path = root / ".github/inventory-runtime-pins.json"
    base, runtime = json.loads(base_path.read_text()), json.loads(runtime_path.read_text())
    if (base.get("schema_version") != "sourcebastion.base-image-pins/1"
            or runtime.get("schema_version") != "sourcebastion.inventory-runtime-pins/1"):
        raise ValueError("python-base-pin-schema-invalid")
    images = [row for row in base["images"] if row["name"] == "python"]
    if len(images) != 1 or images[0]["upstream_repository"] != "docker.io/library/python":
        raise ValueError("python-base-official-pin-required")
    tag, digest, native = resolve(version, runtime["alpine"])
    images[0].update(upstream_tag=tag, digest=digest)
    runtime.update(python=version, python_image=f"python:{tag}@{digest}", python_native_manifests=native)
    dockerfile = root / "images/Dockerfile"
    text, count = re.subn(r"^ARG PYTHON_BASE=.*$", "ARG PYTHON_BASE=docker.io/library/python@" + digest,
                         dockerfile.read_text(), flags=re.MULTILINE)
    if count != 1:
        raise ValueError("python-base-dockerfile-pin-required")
    text, count = re.subn(r"^ARG PYTHON_VERSION=.*$", "ARG PYTHON_VERSION=" + version, text, flags=re.MULTILINE)
    if count != 1:
        raise ValueError("python-base-dockerfile-version-required")
    return {base_path: json.dumps(base, indent=2) + "\n", runtime_path: json.dumps(runtime, indent=2) + "\n",
            dockerfile: text, root / "PYTHON_VERSION": version + "\n"}
