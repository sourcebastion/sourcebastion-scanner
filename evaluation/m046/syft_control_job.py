"""Trusted UID-65534 stdout redirection, then exec the pinned Syft control.

The existing controller owns deadlines, cgroups, diagnostics and post-drain raw
capture. This shim does not install, import or execute anything from /source.
"""

import os
import sys

BINARY = "/candidate/binary"
RAW = "/work/raw.json"


def launch(cpes):
    if cpes not in {"on", "off", "extended"}:
        raise ValueError("expected explicit CPE control")
    binary = "/opt/m046/bin/m046-syft" if cpes == "extended" else BINARY
    command = [
        binary,
        "--mode",
        "extended" if cpes == "extended" else "control",
        "--root",
        "/source",
        "--generate-cpes=" + str(cpes == "on").lower(),
        "--timeout",
        "150s",
    ]
    if cpes == "extended":
        command += [
            "--python",
            "/opt/m046/venv/bin/python",
            "--frontend",
            "/opt/m046/frontend/evaluation/m046/static_cli.py",
        ]
    descriptor = os.open(RAW, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        # The root controller intentionally lacks DAC_OVERRIDE. Give it read
        # access after UID drain without adding any capture capability.
        os.fchmod(descriptor, 0o644)
        os.dup2(descriptor, 1, inheritable=True)
    finally:
        if descriptor != 1:
            os.close(descriptor)
    os.execv(binary, command)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("one explicit CPE control required")
    launch(sys.argv[1])
