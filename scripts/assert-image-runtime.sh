#!/usr/bin/env bash
# Verify the final image identity, Python pin and runtime contents.
set -euo pipefail
if [[ $# -ne 1 ]]; then
  echo "usage: $0 IMAGE" >&2
  exit 2
fi
image=$1
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
expected_python="$(python3 "$root/scripts/python_version.py" current)"
docker run --rm -i --entrypoint python3 "$image" - "$expected_python" \
  "$(cat "$root/.github/bundled-native-libraries.json")" \
  "$(cat "$root/third-party-notices/manifest.json")" \
  "$(sha256sum "$root/third-party-notices/SOURCE-AVAILABILITY.md")" <<'PY'
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import pwd
import re
import shutil
import sys
import tempfile
from pathlib import Path

assert os.getuid() != 0, "image defaults to root"
assert pwd.getpwuid(os.getuid()).pw_name == "sourcebastion", "wrong default user"
assert os.environ.get("HOME") == "/home/sourcebastion", "wrong HOME"
assert Path.cwd() == Path("/scan"), "wrong working directory"
assert tuple(sys.version_info[:3]) == tuple(map(int, sys.argv[1].split("."))), "wrong Python version"
for directory in [Path("/scan"), Path.home() / ".cache"]:
    with tempfile.TemporaryFile(dir=directory) as handle:
        handle.write(b"runtime write probe")
assert importlib.util.find_spec("pip") is not None, "pip required for dependency discovery"
for executable in ["npm", "gitleaks", "grype", "kics", "semgrep", "sourcebastion"]:
    assert shutil.which(executable), f"missing runtime tool: {executable}"
for executable in ["gcc", "g++", "make", "rustc"]:
    assert not shutil.which(executable), f"unexpected build tool: {executable}"
assert not Path("/app/setup.py").exists(), "build context leaked into runtime"
# Inspect installed wheel data without loading any bundled shared library.
notices = Path("/usr/local/share/sourcebastion/third-party-notices")
manifest = json.loads((notices / "manifest.json").read_text())
assert manifest == json.loads(sys.argv[3]), "wrong retained notice manifest"
availability = hashlib.sha256((notices / "SOURCE-AVAILABILITY.md").read_bytes()).hexdigest()
assert availability == sys.argv[4].split()[0], "wrong source directions"
covered = set()
for component in manifest["components"]:
    for name, digest in component["license_files"].items():
        actual = hashlib.sha256((notices / component["id"] / name).read_bytes()).hexdigest()
        assert actual == digest, f"missing/changed license: {component['id']}/{name}"
    covered.update(component["native_sha256"])
observed = []
for distribution in importlib.metadata.distributions():
    for member in distribution.files or []:
        path = Path(str(member))
        vendored = any(part.endswith(".libs") for part in path.parts[:-1])
        vendored |= "/semgrep/bin/libs/" in "/" + str(member)
        vendored |= path.name.startswith("lib") and ".so" in path.name
        if not vendored or ".so" not in path.name:
            continue
        raw = distribution.locate_file(member).read_bytes()
        assert raw.startswith(b"\x7fELF"), f"non-ELF bundled library: {member}"
        digest = hashlib.sha256(raw).hexdigest()
        assert digest in covered, f"bundled library lacks retained notice: {member}"
        observed.append({"distribution": re.sub(r"[-_.]+", "-", distribution.metadata["Name"]).lower(),
                         "version": distribution.version, "path": str(member),
                         "bytes": len(raw), "sha256": digest})
target = "musllinux_1_2_" + platform.machine()
expected = [{key: row[key] for key in ("distribution", "version", "path", "bytes", "sha256")}
            for row in json.loads(sys.argv[2])["targets"][target]]
# Wheel installers spread .data/{purelib,platlib} into site-packages (PEP 427).
# Keep the file's installed path, owner, version, size and bytes exact.
def installed_native_path(path):
    return re.sub(r"^[^/]+\.data/(?:purelib|platlib)/", "", path)

for row in expected:
    row["path"] = installed_native_path(row["path"])
order = lambda row: (row["distribution"], row["path"])
if sorted(observed, key=order) != sorted(expected, key=order):
    print("Expected bundled natives:", json.dumps(sorted(expected, key=order)))
    print("Observed bundled natives:", json.dumps(sorted(observed, key=order)))
    raise AssertionError("installed bundled native set differs from reviewed manifest")
print(f"{target}: {len(observed)} bundled native files, retained licenses and source directions verified")
print(f"sourcebastion user, Python {sys.argv[1]}, writable scan/cache paths and runtime-only contents verified")
PY
