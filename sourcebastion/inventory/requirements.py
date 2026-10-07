"""Static pip text grammar for local dependency inventory.

No package manager, installer, interpreter or metadata service is invoked. This
module retains declaration semantics; include/constraint resolution and engine
integration are separate steps. Diagnostics contain stable codes, not raw URLs.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import posixpath
import re
import shlex
import time

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

from .inputs import InputRefusal, relative_path

VERSION = "sourcebastion.pip-requirements/1"
MAX_LOGICAL_LINE = 16384
HASH = re.compile(r"sha256:[0-9a-fA-F]{64}|sha384:[0-9a-fA-F]{96}|sha512:[0-9a-fA-F]{128}")
REFERENCE = re.compile(r"^(?:(-[rc])\s*|(--requirement|--constraint)(?:=|\s+))(.+)$")
PREFIX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\s*\[[^\]]+\])?\s*")
MAX_RECORDS = 100000
MAX_NESTING = 32
MAX_NUMERIC_RUN = 128


@dataclass(frozen=True)
class RequirementLine:
    line: int
    name: str
    specifier: str
    exact_version: str | None
    marker: str | None
    extras: tuple
    hashes: tuple
    direct_reference: bool = False


@dataclass(frozen=True)
class ReferenceLine:
    line: int
    kind: str
    target: str | None
    reason: str | None = None


@dataclass(frozen=True)
class Document:
    path: str
    sha256: str
    requirements: tuple
    references: tuple
    disposition: str
    reason: str
    parser: str = VERSION


def outside_quotes(text):
    quote = None
    escaped = False
    for index, character in enumerate(text):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if quote:
            if character == quote:
                quote = None
        elif character in {"'", '"'}:
            quote = character
        else:
            yield index, character


def strip_comment(text):
    unquoted = {index for index, _character in outside_quotes(text)}
    for index, character in enumerate(text):
        if character == "#" and (index == 0 or text[index - 1].isspace()):
            if index not in unquoted:
                raise InputRefusal("unsupported-quoted-comment")
            return text[:index].strip()
    return text.strip()


def logical_lines(text, deadline):
    pending = ""
    start = 1
    continuing = False
    for number, physical in enumerate(text.splitlines(), 1):
        if time.monotonic() > deadline:
            raise InputRefusal("input-deadline-exceeded")
        if not continuing:
            start = number
        comment = physical.lstrip().startswith("#")
        continued = physical.endswith("\\") and not comment
        pending += physical[:-1] if continued else (" " + physical if comment else physical)
        if len(pending) > MAX_LOGICAL_LINE:
            raise InputRefusal("requirement-line-budget-exceeded")
        if continued:
            continuing = True
            continue
        line = strip_comment(pending)
        pending = ""
        continuing = False
        if line and not line.startswith("#"):
            yield start, line
    if pending:
        raise InputRefusal("unterminated-requirement-continuation")


def target_path(source, target):
    # Shell syntax and URL syntax never become includes. Quoted literal local
    # paths are permitted, but no shell expansion or globbing is performed.
    if (
        not target
        or target.startswith("/")
        or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", target)
        or "\x00" in target
        or "\\" in target
    ):
        raise InputRefusal("outside-source-reference")
    joined = posixpath.normpath(posixpath.join(posixpath.dirname(source), target))
    if joined == ".." or joined.startswith("../"):
        raise InputRefusal("outside-source")
    return relative_path(joined)


def reference_target(text):
    try:
        tokens = shlex.split(text)
    except ValueError:
        raise InputRefusal("invalid-reference-syntax") from None
    if len(tokens) != 1 or tokens[0].startswith("-"):
        raise InputRefusal("unsupported-reference-options")
    return tokens[0]


def split_hash_options(text):
    index = next(
        (
            i
            for i, char in outside_quotes(text)
            if char == "-" and text[i : i + 2] == "--" and (i == 0 or text[i - 1].isspace())
        ),
        None,
    )
    if index is None:
        return text, ()
    try:
        tokens = shlex.split(text[index:])
    except ValueError:
        raise InputRefusal("invalid-requirement-option-syntax") from None
    hashes = []
    cursor = 0
    while cursor < len(tokens):
        token = tokens[cursor]
        cursor += 1
        if token == "--hash" and cursor < len(tokens):
            value = tokens[cursor]
            cursor += 1
        elif token.startswith("--hash="):
            value = token[len("--hash=") :]
        else:
            raise InputRefusal("unsupported-requirement-option")
        if not HASH.fullmatch(value):
            raise InputRefusal("invalid-requirement-hash")
        hashes.append(value.lower())
    return text[:index].strip(), tuple(sorted(hashes))


def parse_requirement(number, text):
    text, hashes = split_hash_options(text)
    if re.search(r"\d{" + str(MAX_NUMERIC_RUN + 1) + r",}", text):
        raise InputRefusal("requirement-complexity-budget-exceeded")
    depth = 0
    lexical = []
    for _index, character in outside_quotes(text):
        lexical.append(character)
        if character == "(":
            depth += 1
            if depth > MAX_NESTING:
                raise InputRefusal("requirement-complexity-budget-exceeded")
        elif character == ")":
            depth -= 1
    if len(re.findall(r"\b(?:and|or)\b", "".join(lexical))) > 128:
        raise InputRefusal("requirement-complexity-budget-exceeded")
    try:
        requirement = Requirement(text)
    except (ValueError, RecursionError):
        raise InputRefusal("invalid-requirement") from None
    match = PREFIX.match(text)
    if not match:
        raise InputRefusal("invalid-requirement")
    specifier = text[match.end() :].split(";", 1)[0].strip()
    if specifier.startswith("(") and specifier.endswith(")"):
        specifier = specifier[1:-1].strip()
    direct_reference = requirement.url is not None
    if direct_reference:
        # Source hash and locator preserve evidence. Never emit credentials,
        # tokens, local paths or query strings from a direct-reference URL.
        specifier = "direct-reference"
    exact = None
    specs = list(requirement.specifier)
    if any(not item.version for item in specs):
        raise InputRefusal("invalid-requirement")
    exacts = [item.version for item in specs if item.operator == "==" and "*" not in item.version]
    if not direct_reference and exacts:
        for candidate in exacts:
            try:
                Version(candidate)
            except ValueError:
                raise InputRefusal("invalid-selected-version") from None
        try:
            compatible = sorted(
                {candidate for candidate in exacts if requirement.specifier.contains(candidate, prereleases=True)}
            )
        except (ValueError, RecursionError):
            raise InputRefusal("invalid-version-selection") from None
        if not compatible:
            raise InputRefusal("conflicting-requirement-specifiers")
        exact = compatible[0]
    return RequirementLine(
        number,
        canonicalize_name(requirement.name),
        specifier,
        exact,
        str(requirement.marker) if requirement.marker else None,
        tuple(sorted(canonicalize_name(extra) for extra in requirement.extras)),
        hashes,
        direct_reference,
    )


def parse(path, content, *, explicit=False, deadline=None, max_records=MAX_RECORDS):
    path = relative_path(path)
    if not isinstance(content, bytes):
        raise TypeError("static parser requires exact source bytes")
    if len(content) > 2 * 1024 * 1024:
        raise InputRefusal("input-file-budget-exceeded")
    if isinstance(max_records, bool) or not isinstance(max_records, int) or not 0 <= max_records <= MAX_RECORDS:
        raise ValueError("invalid-parser-record-limit")
    if deadline is None:
        deadline = time.monotonic() + 150
    sha256 = hashlib.sha256(content).hexdigest()
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return Document(path, sha256, (), (), "malformed", "invalid-input-encoding")
    requirements, references = [], []
    recognized = explicit or bool(re.fullmatch(r"requirements(?:[-_.].*)?\.(?:txt|in|pip)", posixpath.basename(path)))
    meaningful = False
    failures = []
    try:
        for count, (number, line) in enumerate(logical_lines(text, deadline), 1):
            if count > max_records:
                raise InputRefusal("requirement-record-budget-exceeded")
            if "${" in line:
                meaningful = True
                failures.append("unsupported-environment-substitution")
                continue
            reference = REFERENCE.fullmatch(line)
            if reference:
                short, long, target = reference.groups()
                kind = "constraint" if short == "-c" or long == "--constraint" else "include"
                meaningful = True
                local = None
                try:
                    local = reference_target(target)
                    references.append(ReferenceLine(number, kind, target_path(path, local)))
                except InputRefusal as refusal:
                    failures.append(refusal.reason)
                    # Preserve a refused local reference as data. URLs and
                    # credentials never enter diagnostics or reference fields.
                    if (
                        local is None
                        or local.startswith("/")
                        or "\\" in local
                        or len(local) > 4096
                        or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", local)
                        or any(ord(c) < 32 for c in local)
                    ):
                        local = None
                    references.append(ReferenceLine(number, kind, local, refusal.reason))
                continue
            if line.startswith("-"):
                failures.append("unsupported-requirement-option")
                continue
            try:
                record = parse_requirement(number, line)
                requirements.append(record)
                meaningful = meaningful or bool(record.specifier or record.marker or record.extras or record.hashes)
                if record.direct_reference:
                    failures.append("unsupported-direct-reference")
            except InputRefusal as refusal:
                failures.append(refusal.reason)
    except InputRefusal as refusal:
        failures.append(refusal.reason)
    if failures:
        if not recognized and not meaningful and not any("budget" in code or "deadline" in code for code in failures):
            return Document(path, sha256, (), (), "ignored", "non-dependency-prose")
        reason = failures[0]
        disposition = (
            "budget-exceeded"
            if "budget" in reason or "deadline" in reason
            else (
                "unsafe"
                if reason in {"outside-source-reference", "outside-source", "unsafe-input-path"}
                else ("unsupported" if reason.startswith("unsupported-") else "malformed")
            )
        )
        return Document(path, sha256, (), tuple(references), disposition, reason)
    if not recognized and not meaningful:
        return Document(
            path, sha256, (), (), "ignored", "ambiguous-bare-declarations" if requirements else "empty-candidate"
        )
    return Document(path, sha256, tuple(requirements), tuple(references), "parsed", "static-input")
