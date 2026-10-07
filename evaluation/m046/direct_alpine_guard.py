"""Independent finite Docker cleanup owner; never handles scanned input."""

import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import resource
import select
import signal
import subprocess
import time

DOCKER = ["docker", "--host", "unix:///var/run/docker.sock"]


def child_limits(parent, max_bytes=64 * 1024**2):
    resource.setrlimit(resource.RLIMIT_FSIZE, (max_bytes,) * 2)
    # A detached watchdog owns Docker cleanup; a dead controller must not leave
    # a CLI still submitting/start-attaching work after cleanup has begun.
    if ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(125)


def watch(descriptor, name, output, *, docker=DOCKER, seconds=90, grace=30, cidfile=None):
    if not re.fullmatch(r"m046-direct-alpine-[0-9a-f]{32}", name):
        raise ValueError("specific owned Docker name required")
    reason = "deadline"
    if select.select([descriptor], [], [], seconds)[0]:
        reason = "controller-completed" if os.read(descriptor, 1) == b"D" else "controller-disconnected"
    os.close(descriptor)
    until = time.monotonic() + (0 if reason == "controller-completed" else grace)
    attempts, identifiers, cid_errors = [], set(), []
    while True:
        try:
            if cidfile is not None and (cidfile.exists() or cidfile.is_symlink()):
                try:
                    if cidfile.is_symlink() or not cidfile.is_file() or cidfile.stat().st_size > 65:
                        raise ValueError("uncertain controller CID file")
                    identifier = cidfile.read_text().strip()
                    if not re.fullmatch(r"[0-9a-f]{64}", identifier):
                        raise ValueError("invalid controller CID")
                    identifiers.add(identifier)
                except (OSError, ValueError) as error:
                    cid_errors.append(str(error)[:256])
            result = subprocess.run([*docker, "rm", "--force", name], capture_output=True, timeout=5)
            absent = result.returncode == 0 or ("No such container: " + name) in result.stderr.decode(errors="replace")
            attempts.append({"returncode": result.returncode, "removed_or_absent": absent})
        except subprocess.TimeoutExpired:
            attempts.append({"timeout": True, "removed_or_absent": False})
        except OSError as error:
            attempts.append({"error": str(error)[:256], "removed_or_absent": False})
        if time.monotonic() >= until:
            break
        time.sleep(0.1)
    receipt = {
        "reason": reason,
        "container_name": name,
        "attempts": attempts,
        "known_container_ids": sorted(identifiers),
        "cid_errors": sorted(set(cid_errors)),
        "deadline_seconds": seconds,
        "disconnect_cleanup_poll_seconds": grace,
        "submission_scope": "normal completion follows reaped CLI submissions; disconnect polls are best effort and never qualify parent success",
        "cleanup_confirmed": attempts[-1]["removed_or_absent"] and not cid_errors,
    }
    with output.open("x") as stream:
        json.dump(receipt, stream, sort_keys=True)
        stream.write("\n")
    return 0 if receipt["cleanup_confirmed"] else 2


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fd", type=int, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cidfile", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(watch(args.fd, args.name, args.output, cidfile=args.cidfile))
