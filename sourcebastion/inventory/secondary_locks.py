"""Conservative Bundler/Composer source enumeration without executing projects.

Graph controls remain explicit losses. These readers do not resolve package
selectors, evaluate Ruby/PHP, establish installed state or borrow folder roots.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from urllib.parse import urlsplit

from .inputs import InputRefusal
from .npm_sources import Parser as JsonParser

VERSION = "sourcebastion.secondary-locks/1"
FORMATS = {"bundler-lock": "gem", "composer-lock": "composer"}
NUMERIC = re.compile(r"[0-9]{1,10}(?:\.[0-9]{1,10}){0,3}")
GEM_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
COMPOSER_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,99}/[a-z0-9][a-z0-9_.-]{0,99}")


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    locator: str
    scopes: tuple
    registry_sha256: str | None = None
    graph_locator: str | None = None


@dataclass(frozen=True)
class Document:
    disposition: str
    reason: str
    packages: tuple = ()


def composer(content, *, deadline, check, max_records):
    parser = JsonParser(deadline, check, max_records)
    data = parser.load(content)
    partial, packages, names = set(), [], set()
    known = {
        "_readme",
        "content-hash",
        "packages",
        "packages-dev",
        "aliases",
        "minimum-stability",
        "stability-flags",
        "prefer-stable",
        "prefer-lowest",
        "platform",
        "platform-dev",
        "platform-overrides",
        "plugin-api-version",
    }
    if set(data) - known:
        partial.add("unsupported-composer-lock-controls")
    if type(data.get("content-hash")) is not str or not re.fullmatch(r"[a-f0-9]{32}", data["content-hash"]):
        partial.add("unassessed-composer-manifest-binding")
    for field in ("aliases", "stability-flags", "platform", "platform-dev", "platform-overrides"):
        if data.get(field):
            partial.add("unassessed-composer-selection-controls")
    for field, scope in (("packages", "runtime"), ("packages-dev", "development")):
        rows = data.get(field)
        if type(rows) is not list:
            raise InputRefusal("invalid-composer-package-table")
        for index, row in enumerate(rows):
            parser.retain()
            row = parser.mapping(row)
            if "type" in row and type(row["type"]) is not str:
                partial.add("unsupported-composer-package-type")
                continue
            for source_field in ("source", "dist"):
                if source_field in row and type(row[source_field]) is not dict:
                    partial.add("unsupported-composer-artifact-source")
            if type(row.get("extra")) is dict and row["extra"].get("branch-alias"):
                partial.add("unassessed-composer-selection-controls")
            name = parser.text(row.get("name"), 201)
            if not COMPOSER_NAME.fullmatch(name):
                raise InputRefusal("unsupported-composer-package-name")
            if name in names:
                raise InputRefusal("duplicate-composer-locked-package")
            names.add(name)
            version = parser.text(row.get("version"), 256)
            if version.startswith("v"):
                version = version[1:]
            if not NUMERIC.fullmatch(version):
                partial.add("unassessed-composer-selected-version")
                continue
            # Local/path artifacts do not establish registry package identity.
            if (type(row.get("dist")) is dict and row["dist"].get("type") == "path") or row.get(
                "type"
            ) == "metapackage":
                partial.add("unsupported-composer-local-or-virtual-package")
                continue
            graph = None
            for control in ("require", "require-dev", "provide", "replace", "conflict"):
                if control in row:
                    values = parser.mapping(row[control])
                    if values:
                        partial.add("unassessed-composer-dependency-graph")
                        graph = f"/{field}/{index}/{control}"
            packages.append(Package(name, version, f"/{field}/{index}", (scope,), graph_locator=graph))
    return Document(
        "unsupported" if partial else "parsed",
        sorted(partial)[0] if partial else "static-composer-lock",
        tuple(packages),
    )


def bundler(content, *, deadline, check, max_records):
    parser = JsonParser(deadline, check, max_records)
    if type(content) is not bytes or len(content) > 2 * 1024 * 1024:
        raise InputRefusal("bundler-input-file-budget-exceeded")
    text = content.decode("utf-8")
    section, sections, remote, in_specs, current = None, set(), None, False, None
    packages, partial, names, platforms, direct_names = [], set(), set(), [], set()
    had_specs = False
    for number, line in enumerate(text.split("\n"), 1):
        parser.step()
        line = line.removesuffix("\r")
        if any(ord(c) < 32 or 127 <= ord(c) < 160 for c in line):
            raise InputRefusal("invalid-bundler-source-control")
        if not line:
            continue
        if line[0] != " ":
            if line not in {"GEM", "PLATFORMS", "DEPENDENCIES", "BUNDLED WITH", "RUBY VERSION", "CHECKSUMS"}:
                raise InputRefusal("unsupported-bundler-source-section")
            if line in sections:
                raise InputRefusal("unsupported-bundler-multiple-source-contexts")
            section, in_specs, current = line, False, None
            sections.add(line)
            if line in {"RUBY VERSION", "CHECKSUMS"}:
                partial.add("unassessed-bundler-runtime-or-checksums")
            continue
        if section == "GEM":
            if line.startswith("  remote: ") and not in_specs:
                if remote is not None:
                    raise InputRefusal("unsupported-bundler-multiple-remotes")
                value = line[10:]
                try:
                    uri = urlsplit(value)
                    if uri.scheme not in {"http", "https"} or not uri.hostname or any(c.isspace() for c in value):
                        raise ValueError()
                    uri.port
                except ValueError:
                    raise InputRefusal("unsupported-bundler-remote") from None
                remote = hashlib.sha256(value.encode()).hexdigest()
            elif line == "  specs:" and remote is not None and not in_specs:
                in_specs = True
                had_specs = True
            elif in_specs and re.fullmatch(r"    [^ ]+ \([^()]+\)", line):
                parser.retain()
                name, version = line[4:-1].split(" (", 1)
                if not GEM_NAME.fullmatch(name) or not NUMERIC.fullmatch(version):
                    raise InputRefusal("unsupported-bundler-version-or-platform")
                if name in names:
                    raise InputRefusal("duplicate-bundler-selected-package")
                names.add(name)
                packages.append(Package(name, version, f"line:{number}", (), remote))
                current = len(packages) - 1
            elif in_specs and line.startswith("      ") and current is not None:
                # Preserve the located graph loss without guessing endpoint
                # ownership, platform activation or Ruby requirement grammar.
                partial.add("unassessed-bundler-dependency-graph")
                old = packages[current]
                packages[current] = Package(
                    old.name, old.version, old.locator, old.scopes, old.registry_sha256, f"line:{number}"
                )
            else:
                raise InputRefusal("unsupported-bundler-source-grammar")
        elif section == "PLATFORMS":
            if line != "  ruby":
                raise InputRefusal("unsupported-bundler-platform-alternatives")
            platforms.append("ruby")
        elif section == "DEPENDENCIES":
            if not re.fullmatch(r"  [A-Za-z0-9][A-Za-z0-9_.-]{0,99}(?: \([^()]{1,256}\))?", line):
                raise InputRefusal("unsupported-bundler-direct-declaration")
            name = line[2:].split(" (", 1)[0]
            if name in direct_names:
                raise InputRefusal("duplicate-bundler-direct-declaration")
            direct_names.add(name)
            if " (" in line:
                partial.add("unassessed-bundler-root-requirement")
            # Root declaration/activation is not assigned by name alone.
        elif section == "BUNDLED WITH":
            if not re.fullmatch(r"   [0-9]+(?:\.[0-9]+){1,3}", line):
                raise InputRefusal("unsupported-bundler-runtime-version")
        elif section in {"RUBY VERSION", "CHECKSUMS"}:
            pass
        else:
            raise InputRefusal("invalid-bundler-source-section")
    if (
        not {"GEM", "PLATFORMS", "DEPENDENCIES"}.issubset(sections)
        or remote is None
        or not had_specs
        or platforms != ["ruby"]
    ):
        raise InputRefusal("unsupported-bundler-incomplete-lock")
    if direct_names - names:
        partial.add("unassessed-bundler-missing-direct-package")
    return Document(
        "unsupported" if partial else "parsed",
        sorted(partial)[0] if partial else "static-bundler-lock",
        tuple(packages),
    )


def parse(content, fmt, *, deadline, check, max_records):
    if fmt not in FORMATS or type(max_records) is not int or not 0 <= max_records <= 100000 or not callable(check):
        raise ValueError("trusted-secondary-lock-inputs-required")
    ecosystem = "composer" if fmt == "composer-lock" else "bundler"
    try:
        return (composer if fmt == "composer-lock" else bundler)(
            content, deadline=deadline, check=check, max_records=max_records
        )
    except InputRefusal as error:
        reason = error.reason.replace("npm-", ecosystem + "-")
        if "budget" in reason or "deadline" in reason:
            raise InputRefusal(reason) from None
    except (ValueError, UnicodeError, RecursionError):
        reason = f"invalid-{ecosystem}-source-syntax"
    return Document("unsupported" if reason.startswith(("unsupported-", "unassessed-")) else "failed", reason)
