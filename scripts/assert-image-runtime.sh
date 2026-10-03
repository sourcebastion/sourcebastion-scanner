#!/usr/bin/env bash
# Verify the final image uses the declared non-root identity and writable paths.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 IMAGE VARIANT" >&2
  exit 2
fi

image=$1
variant=$2

docker run --rm -i --entrypoint python3 "$image" - "$variant" <<'PY'
import importlib.util
import os
import pwd
import shutil
import sys
import tempfile
from pathlib import Path

variant = sys.argv[1]
assert os.getuid() != 0, "image defaults to root"
assert pwd.getpwuid(os.getuid()).pw_name == "sourcebastion", "wrong default user"
assert os.environ.get("HOME") == "/home/sourcebastion", "wrong HOME"
assert Path.cwd() == Path("/scan"), "wrong working directory"
for directory in [Path("/scan"), Path.home() / ".cache"]:
    with tempfile.TemporaryFile(dir=directory) as handle:
        handle.write(b"runtime write probe")
if variant == "thin":
    assert importlib.util.find_spec("pip") is None, "thin image retains pip"
    assert importlib.util.find_spec("ensurepip") is None, "thin image can bootstrap pip"
    assert not shutil.which("pip") and not shutil.which("pip3"), "thin image retains pip scripts"
    assert not shutil.which("npm"), "thin image retains npm"
elif variant == "standard":
    assert importlib.util.find_spec("pip") is not None, "standard image requires pip for dependency discovery"
    assert shutil.which("npm"), "standard image requires npm for dependency discovery"
print(f"{variant}: sourcebastion user, writable scan/cache paths, package-manager contract verified")
PY
