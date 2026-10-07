"""Bounded modern Gradle lock input; no project evaluation or resolution."""

from __future__ import annotations

from dataclasses import dataclass
import re

from .inputs import InputRefusal

VERSION = "sourcebastion.gradle-lock/1"
IDENTIFIER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,199}")
REVISION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}")
CONFIGURATION = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,199}")


@dataclass(frozen=True)
class Package:
    line: int
    group: str
    artifact: str
    version: str
    configurations: tuple[str, ...]


@dataclass(frozen=True)
class Document:
    disposition: str
    reason: str
    packages: tuple[Package, ...] = ()
    empty_line: int | None = None
    empty_configurations: tuple[str, ...] = ()


def parse(content, *, check, max_records):
    """Refuse an entire contradictory/unsupported input, never select a prefix."""
    check()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return Document("failed", "invalid-gradle-lock-encoding")
    packages, coordinates, selections, populated = [], set(), {}, set()
    empty_line, empty_configurations = None, ()

    def configs(value, allow_empty=False):
        if not value and allow_empty:
            return ()
        fields = value.split(",")
        if len(fields) > 64:
            raise InputRefusal("gradle-configuration-budget-exceeded")
        result = []
        for field in fields:
            check()
            name = field.strip(" \t")
            if not CONFIGURATION.fullmatch(name) or name in result:
                return None
            result.append(name)
        return tuple(sorted(result))

    for number, raw in enumerate(text.split("\n"), 1):
        check()
        raw = raw.removesuffix("\r")
        if any(ord(character) < 32 and character != "\t" or ord(character) == 127 for character in raw):
            return Document("failed", "invalid-gradle-lock-control")
        line = raw.strip(" \t")
        if not line or line.startswith("#"):
            continue
        if empty_line is not None:
            return Document("failed", "nonterminal-gradle-empty-marker")
        if line.count("=") != 1:
            return Document("unsupported", "unassessed-gradle-lock-representation")
        coordinate, raw_configs = line.split("=")
        if coordinate == "empty":
            empty_configurations = configs(raw_configs, allow_empty=True)
            if empty_configurations is None:
                return Document("failed", "invalid-gradle-configurations")
            if populated.intersection(empty_configurations):
                return Document("failed", "contradictory-gradle-empty-configuration")
            empty_line = number
            continue
        fields = coordinate.split(":")
        if len(fields) != 3 or not all(IDENTIFIER.fullmatch(value) for value in fields[:2]):
            return Document("unsupported", "unassessed-gradle-coordinate")
        group, artifact, revision = fields
        if (
            not REVISION.fullmatch(revision)
            or revision.lower() in {"latest", "release", "head", "main", "master", "unknown"}
            or revision.lower().startswith("latest.")
        ):
            return Document("unsupported", "unassessed-gradle-version")
        configurations = configs(raw_configs)
        if configurations is None:
            return Document("failed", "invalid-gradle-configurations")
        if (group, artifact, revision) in coordinates:
            return Document("failed", "duplicate-gradle-coordinate")
        coordinates.add((group, artifact, revision))
        for configuration in configurations:
            check()
            key = (group, artifact, configuration)
            if key in selections and selections[key] != revision:
                return Document("failed", "contradictory-gradle-locked-version")
            selections[key] = revision
            populated.add(configuration)
        if len(packages) >= max_records:
            raise InputRefusal("gradle-occurrence-budget-exceeded")
        packages.append(Package(number, group, artifact, revision, configurations))
    if empty_line is None:
        return Document("unsupported", "missing-modern-gradle-empty-marker")
    return Document("parsed", "static-gradle-lock", tuple(packages), empty_line, empty_configurations)
