"""Bounded trusted legacy Yarn grammar without project/tool resolution."""

import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import time

from .inputs import InputRefusal, relative_path

VERSION = "sourcebastion.yarn-legacy/1"
MANIFEST_SHA256 = "b62b2946c9f450dc2f1e439135223b296da5d474e1e4c099c1514c07dc5b8327"


def verify_vendor():
    base = Path(__file__).resolve().parent
    raw = (base / "vendor/yarn-syml-manifest.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise InputRefusal("yarn-grammar-manifest-mismatch")
    manifest = json.loads(raw)
    for name, checksum in manifest["files"].items():
        if (
            relative_path(name) != name
            or hashlib.sha256((base / "vendor/yarn-syml" / name).read_bytes()).hexdigest() != checksum
        ):
            raise InputRefusal("yarn-grammar-source-mismatch")
    return MANIFEST_SHA256


def parse(content, *, deadline, check):
    if type(content) is not bytes or not callable(check):
        raise TypeError("trusted-yarn-bytes-and-check-required")
    if type(deadline) not in {int, float} or not math.isfinite(deadline):
        raise ValueError("invalid-controller-deadline")
    if len(content) > 2 * 1024 * 1024:
        raise InputRefusal("input-file-budget-exceeded")
    try:
        source = content.decode("utf-8-sig")
    except UnicodeError:
        raise InputRefusal("invalid-yarn-utf8") from None
    if not re.match(r"^(#.*(?:\r?\n))*?#\s+yarn\s+lockfile\s+v1\r?\n", source, re.I):
        raise InputRefusal("unsupported-yarn-classic-header")
    lines = source.splitlines()
    if len(lines) > 100000:
        raise InputRefusal("yarn-line-budget-exceeded")
    for line in lines:
        check()
        indent = len(line) - len(line.lstrip(" "))
        if indent > 64 or indent % 2 or line[indent:].startswith("\t"):
            raise InputRefusal("unsupported-yarn-indentation")
    verify_vendor()
    check()
    remaining = deadline - time.monotonic()
    if not 0 < remaining <= 150:
        raise InputRefusal("yarn-parser-deadline-exceeded")
    request = json.dumps(
        {"schema_version": VERSION, "source": source}, ensure_ascii=True, separators=(",", ":")
    ).encode()
    if len(request) > 16 * 1024 * 1024:
        raise InputRefusal("yarn-parser-input-budget-exceeded")
    remaining = deadline - time.monotonic()
    if not 0 < remaining <= 150:
        raise InputRefusal("yarn-parser-deadline-exceeded")
    try:
        result = subprocess.run(
            [
                "/usr/bin/node",
                "--disallow-code-generation-from-strings",
                "--v8-pool-size=1",
                "--max-old-space-size=256",
                str(Path(__file__).resolve().with_name("yarn_legacy.cjs")),
            ],
            input=request,
            capture_output=True,
            timeout=remaining,
            cwd=str(Path(__file__).resolve().parent),
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
    except subprocess.TimeoutExpired:
        raise InputRefusal("yarn-parser-deadline-exceeded") from None
    except OSError:
        raise InputRefusal("yarn-parser-runtime-unavailable") from None
    check()
    if time.monotonic() > deadline:
        raise InputRefusal("yarn-parser-deadline-exceeded")
    if result.returncode != 0 or len(result.stdout) > 64 * 1024 * 1024 or len(result.stderr) > 64 * 1024 * 1024:
        raise InputRefusal("yarn-legacy-parse-refused")
    try:
        response = json.loads(result.stdout)
        if (
            type(response) is not dict
            or set(response) != {"schema_version", "entries"}
            or response["schema_version"] != "sourcebastion.yarn-legacy-result/1"
            or type(response["entries"]) is not list
            or len(response["entries"]) > 100000
        ):
            raise ValueError
        entries = []
        seen = set()
        for entry in response["entries"]:
            check()
            if (
                type(entry) is not dict
                or set(entry) != {"keys", "record"}
                or type(entry["keys"]) is not list
                or not entry["keys"]
                or len(entry["keys"]) > 100000
                or type(entry["record"]) is not dict
            ):
                raise ValueError
            for key in entry["keys"]:
                check()
                if type(key) is not str or key in seen:
                    raise ValueError
                seen.add(key)
            entries.append((tuple(entry["keys"]), entry["record"]))
        return tuple(entries)
    except InputRefusal:
        raise
    except (ValueError, TypeError, RecursionError):
        raise InputRefusal("invalid-yarn-parser-response") from None
