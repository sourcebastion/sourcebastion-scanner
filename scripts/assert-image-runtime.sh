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
docker run --rm -i --entrypoint python3 "$image" - "$expected_python" <<'PY'
import importlib.util
import os
import pwd
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
print(f"sourcebastion user, Python {sys.argv[1]}, writable scan/cache paths and runtime-only contents verified")
PY
