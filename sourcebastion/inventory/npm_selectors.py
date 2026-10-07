"""Batch npm range checks using pinned upstream grammar, never project tooling.

The enclosing controller owns the shared cgroup/process/deadline boundary.
This trusted parser subprocess receives only bounded version/range strings.
"""

import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import time

from .inputs import InputRefusal, relative_path

VERSION = "sourcebastion.npm-selectors/1"
RESULTS = frozenset({"match", "nonmatch", "invalid-version", "invalid-range"})
MAX_BYTES = 64 * 1024 * 1024


def _refuse(reason):
    raise InputRefusal(reason) from None


def verify_vendor():
    """Verify installed parser bytes; image custody remains a controller duty."""
    base = Path(__file__).resolve().parent
    raw = (base / "vendor/npm-semver-manifest.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != "85a15ddf20cf437c7b886df975c3e897daa4cfcd494df85b13091053132b54f3":
        _refuse("npm-parser-manifest-mismatch")
    manifest = json.loads(raw)
    root = base / "vendor/npm-semver"
    for path, checksum in manifest["files"].items():
        if relative_path(path) != path or hashlib.sha256((root / path).read_bytes()).hexdigest() != checksum:
            _refuse("npm-parser-source-mismatch")
    return hashlib.sha256(raw).hexdigest()


def evaluate(queries, *, deadline, check):
    """Return one result per supplied pair; no version selection or resolution.

    Callers prove candidate identities and source contexts. An answer is only
    range compatibility under pinned npm grammar. The existing semantic ledger
    and remaining outer deadline apply to admission and response validation.
    """
    if type(queries) not in {list, tuple} or len(queries) > 100000 or not callable(check):
        raise TypeError("bounded-controller-selector-inputs-required")
    if type(deadline) not in {int, float} or not math.isfinite(deadline):
        raise ValueError("invalid-controller-deadline")
    remaining = deadline - time.monotonic()
    if not 0 < remaining <= 150:
        _refuse("npm-selector-deadline-exceeded")
    size = 0
    for pair in queries:
        check()
        if type(pair) not in {list, tuple} or len(pair) != 2:
            _refuse("invalid-npm-selector-query")
        version, selector = pair
        if type(version) is not str or type(selector) is not str or len(version) > 256 or len(selector) > 16384:
            _refuse("npm-selector-query-budget-exceeded")
        if any(ord(c) < 32 or 127 <= ord(c) < 160 for c in version + selector):
            _refuse("invalid-npm-selector-text")
        if re.search(r"\d{129,}", version + selector) or len(re.split(r"\s+|\|\|", selector)) > 128:
            _refuse("npm-selector-query-budget-exceeded")
        # Reserve worst-case JSON escaping before building the full request.
        size += 32 + 12 * (len(version) + len(selector))
        if size > MAX_BYTES:
            _refuse("npm-selector-input-budget-exceeded")
    verify_vendor()
    check()
    if not queries:
        return ()
    data = json.dumps({"schema_version": VERSION, "queries": queries}, separators=(",", ":"), allow_nan=False).encode()
    if len(data) > MAX_BYTES:
        _refuse("npm-selector-input-budget-exceeded")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        _refuse("npm-selector-deadline-exceeded")
    try:
        result = subprocess.run(
            [
                "/usr/bin/node",
                "--disallow-code-generation-from-strings",
                "--v8-pool-size=1",
                "--max-old-space-size=256",
                str(Path(__file__).resolve().with_name("node_selectors.cjs")),
            ],
            input=data,
            capture_output=True,
            timeout=remaining,
            cwd=str(Path(__file__).resolve().parent),
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
    except subprocess.TimeoutExpired:
        _refuse("npm-selector-deadline-exceeded")
    except OSError:
        _refuse("npm-selector-runtime-unavailable")
    check()
    if result.returncode != 0 or len(result.stdout) > MAX_BYTES or len(result.stderr) > MAX_BYTES:
        _refuse("npm-selector-runtime-refused")
    try:
        response = json.loads(result.stdout)
        values = response["results"]
        if (
            set(response) != {"schema_version", "results"}
            or response["schema_version"] != "sourcebastion.npm-selector-results/1"
            or type(values) is not list
            or len(values) != len(queries)
        ):
            _refuse("invalid-npm-selector-response")
        for value in values:
            check()
            if type(value) is not str or value not in RESULTS:
                _refuse("invalid-npm-selector-response")
    except InputRefusal:
        raise
    except (ValueError, KeyError, TypeError):
        _refuse("invalid-npm-selector-response")
    if time.monotonic() > deadline:
        _refuse("npm-selector-deadline-exceeded")
    return tuple(values)
