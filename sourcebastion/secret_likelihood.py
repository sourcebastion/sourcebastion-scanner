"""Advisory reason codes derived from the redacted Gitleaks report."""

import math
import os
from pathlib import PurePosixPath
import re
import stat
from contextlib import ExitStack


_PATH_CLASSES = {
    "test": {"test", "tests", "__tests__", "fixtures", "testdata"},
    "documentation": {"doc", "docs", "documentation", "example", "examples", "samples"},
    "vendor": {"vendor", "vendored", "third_party", "node_modules"},
    "generated": {"generated", "__generated__"},
}

# Use known IDs from the pinned upstream rules. A repository can define
# additional IDs, so a name that merely has a provider prefix proves nothing.
_CREDENTIAL_RULES = {
    "aws-access-token", "aws-amazon-bedrock-api-key-long-lived",
    "aws-amazon-bedrock-api-key-short-lived", "gcp-api-key", "github-app-token",
    "github-fine-grained-pat", "github-oauth", "github-pat", "github-refresh-token",
    "jwt", "jwt-base64", "private-key", "slack-app-token", "slack-bot-token",
    "slack-config-access-token", "slack-config-refresh-token",
    "slack-legacy-bot-token", "slack-legacy-token", "slack-legacy-workspace-token",
    "slack-user-token", "slack-webhook-url", "stripe-access-token",
}

_MAX_FILE_BYTES = 64 * 1024
_MAX_EXACT_CHECKS = 128
_PUBLISHABLE_ASSIGNMENT = re.compile(rb"""(?:stripe_publishable_key|stripe_public_key)[ \t]*[:=][ \t]*(['"])""", re.IGNORECASE)
_PUBLISHABLE_KEY = re.compile(rb"pk_(?:test|live)_[A-Za-z0-9]{24,128}")
_PLACEHOLDER = re.compile(rb"(?:YOUR_(?:SERVICE_)?API_KEY_HERE|<your-api-key>|<your-key>)", re.IGNORECASE)


def _read_regular_file(root, file_path, scan_started_ns):
    parts = PurePosixPath(file_path).parts
    if not parts or parts[0] == "/" or any(part in {"..", ".git"} for part in parts):
        return b""
    if not hasattr(os, "O_NOFOLLOW"):
        return b""
    with ExitStack() as descriptors:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        descriptors.callback(os.close, fd)
        for name in parts[:-1]:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            descriptors.callback(os.close, fd)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        descriptors.callback(os.close, fd)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_FILE_BYTES
                or max(info.st_mtime_ns, info.st_ctime_ns) > scan_started_ns):
            return b""
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(_MAX_FILE_BYTES + 1)
        final = os.fstat(fd)
        stable = (info.st_size, info.st_mtime_ns, info.st_ctime_ns) == (
            final.st_size, final.st_mtime_ns, final.st_ctime_ns
        )
        return data if stable and len(data) <= _MAX_FILE_BYTES else b""


def gitleaks_benign_codes(root, findings, *, scan_started_ns):
    """Inspect a bounded set of exact, single-line generic matches in the scanned tree.

    History findings never use this function. The already-redacted detector
    output supplies the match context and coordinates, never the candidate.
    Only categorical decisions leave the scanner.
    """
    credential_lines = {
        (path, match["StartLine"])
        for path, match in findings
        if isinstance(match.get("RuleID"), str) and match["RuleID"] in _CREDENTIAL_RULES
        and type(match.get("StartLine")) is int
    }
    candidates = []
    for index, (path, match) in enumerate(findings):
        if match.get("RuleID") != "generic-api-key" or match.get("Secret") != "REDACTED":
            continue
        line, start, end = (match.get(key) for key in ("StartLine", "StartColumn", "EndColumn"))
        enclosing = match.get("Match")
        if (not all(type(n) is int for n in (line, start, end)) or not 1 <= line <= _MAX_FILE_BYTES
                or (path, line) in credential_lines or line != match.get("EndLine")
                or not 1 <= start <= end <= _MAX_FILE_BYTES
                or not isinstance(enclosing, str) or len(enclosing) > 512 or enclosing.count("REDACTED") != 1):
            continue
        try:
            before, after = (part.encode("utf-8") for part in enclosing.split("REDACTED"))
        except UnicodeError:
            continue
        if after not in (b'"', b"'") or not before.endswith(after):
            continue
        # Named publishable assignments are identifiable from the redacted
        # context. Check them before using the remaining budget on broad matches.
        publishable_assignment = bool(_PUBLISHABLE_ASSIGNMENT.fullmatch(before))
        candidates.append((not publishable_assignment, path, line, start, end, index, before, after))

    result = {}
    loaded_path = None
    lines = []
    for broad, path, line, start, end, index, before, after in sorted(candidates)[:_MAX_EXACT_CHECKS]:
        if path != loaded_path:
            loaded_path = path
            try:
                lines = _read_regular_file(root, path, scan_started_ns).split(b"\n")
            except (OSError, ValueError):
                lines = []
        if line > len(lines):
            continue
        source_line = lines[line - 1]
        # Anchor to the exact redacted span. A truncated or changed line is
        # insufficient, including differently encoded detector coordinates.
        if end > len(source_line):
            continue
        span = source_line[start - 1:end]
        if not span.startswith(before) or not span.endswith(after):
            continue
        value = span[len(before):-len(after)]
        if not broad and _PUBLISHABLE_KEY.fullmatch(value):
            result[index] = "v1:public-key"
        elif _PLACEHOLDER.fullmatch(value):
            result[index] = "v1:placeholder"
    return result


def gitleaks_likelihood_code(rule_id: object, file_path: object, entropy: object) -> str | None:
    """Classify available evidence without needing the match or secret fields."""
    if not isinstance(rule_id, str):
        return None
    if rule_id in _CREDENTIAL_RULES:
        return "v1:credential-format"
    if rule_id != "generic-api-key":
        return None

    if isinstance(file_path, str) and file_path:
        path = PurePosixPath(file_path.lower())
        directories = set(path.parts[:-1])
        for label, names in _PATH_CLASSES.items():
            if directories & names:
                return f"v1:generic-{label}"
        if path.name.startswith("test_") or path.name.endswith(
            ("_test.go", ".test.js", ".test.ts", ".spec.js", ".spec.ts")
        ):
            return "v1:generic-test"
    if type(entropy) in (float, int) and 0 < entropy <= 8 and math.isfinite(entropy):
        return "v1:generic-entropy"
    return "v1:generic"
