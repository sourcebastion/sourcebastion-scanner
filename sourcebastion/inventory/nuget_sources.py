"""Static NuGet v1/v2 lock facts; framework/RID graphs stay separate.

No restore, MSBuild evaluation, project ownership or installed state is inferred.
Only numeric release ranges are checked here; prerelease/floating selectors
remain unresolved instead of approximating NuGet's full version grammar.
"""

from dataclasses import dataclass
import base64
import binascii
import re

from .inputs import InputRefusal
from .npm_sources import Parser as JsonParser, pointer

VERSION = "sourcebastion.nuget-source/1"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
TARGET = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,199}(?:/[A-Za-z0-9][A-Za-z0-9_.+-]{0,199})?")
REVISION = re.compile(
    r"[0-9]{1,10}(?:\.[0-9]{1,10}){0,3}(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
)
NUMERIC = re.compile(r"[0-9]{1,10}(?:\.[0-9]{1,10}){0,3}")
RANGE = re.compile(r"[0-9A-Za-z.*+_,()\[\] -]{1,256}")


def numeric(value):
    if not NUMERIC.fullmatch(value):
        return None
    parts = tuple(int(part) for part in value.split("."))
    return parts + (0,) * (4 - len(parts))


def satisfies(version, expression):
    """True/False for a small reviewed release grammar, None for unassessed."""
    selected = numeric(version)
    if selected is None:
        return None
    expression = expression.strip()
    bare = numeric(expression)
    if bare is not None:
        return selected >= bare  # NuGet bare versions are minimums, not pins.
    if expression.startswith("[") and expression.endswith("]") and "," not in expression:
        exact = numeric(expression[1:-1].strip())
        return None if exact is None else selected == exact
    if len(expression) < 3 or expression[0] not in "[(" or expression[-1] not in ")]":
        return None
    fields = expression[1:-1].split(",")
    if len(fields) != 2:
        return None
    left, right = (part.strip() for part in fields)
    lower, upper = numeric(left) if left else None, numeric(right) if right else None
    if (left and lower is None) or (right and upper is None) or (not left and not right):
        return None
    if (
        lower is not None
        and upper is not None
        and (lower > upper or lower == upper and (expression[0] != "[" or expression[-1] != "]"))
    ):
        return None
    if (not left and expression[0] != "(") or (not right and expression[-1] != ")"):
        return None
    return (lower is None or selected > lower or selected == lower and expression[0] == "[") and (
        upper is None or selected < upper or selected == upper and expression[-1] == "]"
    )


@dataclass(frozen=True)
class Package:
    target: str
    name: str
    version: str
    locator: str
    requested: str | None
    directness: str
    hashes: tuple
    dependencies: tuple


@dataclass(frozen=True)
class Document:
    disposition: str
    reason: str
    targets: tuple = ()
    packages: tuple = ()


def parse(content, *, deadline, check, max_records):
    if type(max_records) is not int or not 0 <= max_records <= 100000 or not callable(check):
        raise ValueError("trusted-nuget-parser-inputs-required")
    parser = JsonParser(deadline, check, max_records)
    partial, packages, selector_count = set(), [], 0
    try:
        data = parser.load(content)
        if type(data.get("version")) is not int or data["version"] not in {1, 2}:
            raise InputRefusal("unsupported-nuget-lock-version")
        if set(data) != {"version", "dependencies"}:
            raise InputRefusal("unsupported-nuget-lock-controls")
        targets = parser.mapping(data["dependencies"])
        if not targets:
            raise InputRefusal("unsupported-nuget-missing-targets")
        for target, entries in targets.items():
            parser.step()
            if type(target) is not str or not TARGET.fullmatch(target):
                raise InputRefusal("unsupported-nuget-target")
            names = set()
            for supplied, value in parser.mapping(entries).items():
                parser.retain()
                if type(supplied) is not str or not NAME.fullmatch(supplied):
                    raise InputRefusal("unsupported-nuget-name")
                name = supplied.lower()
                if name in names:
                    raise InputRefusal("duplicate-nuget-case-insensitive-name")
                names.add(name)
                value = parser.mapping(value)
                if set(value) - {"type", "resolved", "requested", "contentHash", "dependencies"}:
                    partial.add("unsupported-nuget-package-controls")
                    continue
                kind = value.get("type")
                if type(kind) is not str or kind not in {"Direct", "Transitive", "CentralTransitive"}:
                    partial.add("unsupported-nuget-project-or-package-type")
                    continue
                version = parser.text(value.get("resolved"), 256)
                if not REVISION.fullmatch(version):
                    raise InputRefusal("unsupported-nuget-selected-version")
                requested = parser.text(value["requested"], 256) if "requested" in value else None
                if requested is not None and not RANGE.fullmatch(requested):
                    raise InputRefusal("unsupported-nuget-requested-range")
                if kind == "Direct" and requested is None:
                    partial.add("missing-nuget-requested-version")
                if requested is not None:
                    answer = satisfies(version, requested)
                    if answer is False:
                        raise InputRefusal("contradictory-nuget-requested-version")
                    if answer is None:
                        partial.add("unassessed-nuget-requested-range")
                hashes = ()
                raw_hash = value.get("contentHash")
                if type(raw_hash) is str:
                    try:
                        decoded = base64.b64decode(raw_hash, validate=True)
                        if len(decoded) == 64 and base64.b64encode(decoded).decode() == raw_hash:
                            hashes = (("sha512", decoded.hex()),)
                    except (ValueError, binascii.Error):
                        pass
                if not hashes:
                    partial.add("unassessed-nuget-content-hash")
                dependencies, dependency_names = [], set()
                for dep_name, expression in parser.mapping(value.get("dependencies", {})).items():
                    parser.step()
                    selector_count += 1
                    if selector_count > 500000:
                        raise InputRefusal("nuget-selector-budget-exceeded")
                    if type(dep_name) is not str or not NAME.fullmatch(dep_name):
                        raise InputRefusal("unsupported-nuget-dependency-name")
                    canonical = dep_name.lower()
                    if canonical in dependency_names:
                        raise InputRefusal("duplicate-nuget-dependency-name")
                    dependency_names.add(canonical)
                    expression = parser.text(expression, 256)
                    if not RANGE.fullmatch(expression):
                        raise InputRefusal("unsupported-nuget-dependency-range")
                    dependencies.append((canonical, expression, pointer(dep_name)))
                locator = "/dependencies/" + pointer(target) + "/" + pointer(supplied)
                packages.append(
                    Package(
                        target,
                        name,
                        version,
                        locator,
                        requested,
                        "direct" if kind == "Direct" else "transitive",
                        hashes,
                        tuple(dependencies),
                    )
                )
        return Document(
            "unsupported" if partial else "parsed",
            sorted(partial)[0] if partial else "static-nuget-lock",
            tuple(sorted(targets)),
            tuple(packages),
        )
    except InputRefusal as error:
        reason = error.reason.replace("npm-", "nuget-")
        if "budget" in reason or "deadline" in reason:
            raise InputRefusal(reason) from None
    except (ValueError, UnicodeError, RecursionError):
        reason = "invalid-nuget-source-syntax"
    return Document("unsupported" if reason.startswith("unsupported-") else "failed", reason)
