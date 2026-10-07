"""Registry Yarn lock observations and exact source descriptor mappings."""

from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json
import re

from . import npm_sources, yarn_legacy
from .bounded_yaml import load_documents
from .inputs import InputRefusal

VERSION = "sourcebastion.yarn-sources/1"


def located(kind, value):
    return (
        kind
        + ":sha256:"
        + hashlib.sha256(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()
    )


@dataclass(frozen=True)
class Reference:
    name: str
    expression: str
    descriptor: str
    scope: str
    locator: str
    optional: bool = False
    protocol_supported: bool = True


@dataclass(frozen=True)
class Package:
    key: str
    name: str
    version: str
    locator: str
    descriptors: tuple
    references: tuple = ()
    hashes: tuple = ()
    source_key: str | None = None


@dataclass(frozen=True)
class Document:
    disposition: str
    reason: str
    packages: tuple = ()
    parser: str = VERSION
    blocked_descriptors: frozenset = frozenset()


class Parser(npm_sources.Parser):
    def descriptor(self, value, modern=False):
        value = self.text(value)
        match = re.fullmatch(r"(@[^/]+/[^@]+|[^@/]+)@(.*)", value)
        if not match:
            raise InputRefusal("unsupported-yarn-descriptor")
        name, expression = self.name(match[1]), self.text(match[2], empty=True)
        if modern and not expression.startswith("npm:"):
            raise InputRefusal("unsupported-yarn-descriptor-protocol")
        if expression.startswith("npm:"):
            expression = expression[4:]
        # The maintained npm helper, not this splitter, admits range grammar.
        return name, expression

    def boolean(self, value, modern):
        if modern:
            if type(value) is not str or value not in {"true", "false"}:
                raise InputRefusal("invalid-yarn-boolean")
            return value == "true"
        if type(value) is not bool:
            raise InputRefusal("invalid-yarn-boolean")
        return value

    def parse_entries(self, entries, modern):
        packages = []
        descriptor_counts = {}
        for keys, _raw in entries:
            for key in keys:
                self.step()
                descriptor_counts[key] = descriptor_counts.get(key, 0) + 1
        blocked = frozenset(key for key, count in descriptor_counts.items() if count > 1)
        if blocked:
            self.partial.add("ambiguous-yarn-source-descriptor")
        for ordinal, (keys, raw) in enumerate(entries):
            self.retain()
            try:
                identities = [self.descriptor(key, modern) for key in keys]
                if len({name for name, _expression in identities}) != 1:
                    raise InputRefusal("unsupported-yarn-alias-identity")
                name = identities[0][0]
                raw = self.mapping(raw)
                version = self.version(raw.get("version"))
                locator = located("entry", [ordinal, keys])
                known = {"version", "resolved", "integrity", "dependencies", "optionalDependencies"}
                if modern:
                    known = {
                        "version",
                        "resolution",
                        "checksum",
                        "languageName",
                        "linkType",
                        "dependencies",
                        "peerDependencies",
                        "dependenciesMeta",
                        "peerDependenciesMeta",
                        "bin",
                        "conditions",
                    }
                if set(raw) - known:
                    self.partial.add("unsupported-yarn-package-controls")
                source_key, hashes = None, ()
                if modern:
                    resolution = raw.get("resolution")
                    if resolution is None:
                        self.partial.add("incomplete-yarn-package-resolution")
                    else:
                        resolution = self.text(resolution)
                        matched = re.fullmatch(r"(@[^/]+/[^@]+|[^@/]+)@npm:(.+)", resolution)
                        if not matched or self.name(matched[1]) != name or matched[2] != version:
                            raise InputRefusal("unsupported-yarn-package-resolution")
                    if raw.get("linkType") not in ("hard", "HARD"):
                        self.partial.add("unsupported-yarn-link-type")
                    if "languageName" in raw and raw["languageName"] != "node":
                        raise InputRefusal("unsupported-yarn-package-language")
                    if "checksum" in raw:
                        # This is a Yarn cache-archive digest, not an npm tarball
                        # integrity. Do not relabel it as a downloaded artifact.
                        self.partial.add("unassessed-yarn-cache-checksum")
                    if "conditions" in raw:
                        self.partial.add("unassessed-yarn-platform-conditions")
                else:
                    if "resolved" not in raw:
                        self.partial.add("incomplete-yarn-package-resolution")
                    else:
                        source_key = self.source(raw["resolved"])
                    if "integrity" in raw:
                        hashes = self.hashes(raw["integrity"])
                metadata = self.mapping(raw.get("dependenciesMeta", {}))
                peers = self.mapping(raw.get("peerDependenciesMeta", {}))
                for table in (metadata, peers):
                    for dep_name, controls in table.items():
                        self.step()
                        self.name(dep_name)
                        controls = self.mapping(controls)
                        if set(controls) - {"optional"}:
                            self.partial.add("unsupported-yarn-dependency-controls")
                        if "optional" in controls:
                            self.boolean(controls["optional"], modern)
                references = []
                for field, scope in (
                    ("dependencies", "runtime"),
                    ("optionalDependencies", "optional"),
                    ("peerDependencies", "peer"),
                ):
                    for dep_name, expression in self.mapping(raw.get(field, {})).items():
                        self.retain()
                        dep_name, expression = self.name(dep_name), self.text(expression, empty=True)
                        if modern and scope != "peer" and not expression.startswith("npm:"):
                            self.partial.add("unsupported-yarn-dependency-protocol")
                        dep_meta = peers if scope == "peer" else metadata
                        optional = self.boolean(
                            dep_meta.get(dep_name, {}).get("optional", "false" if modern else False), modern
                        )
                        if field == "dependencies" and dep_name in self.mapping(raw.get("optionalDependencies", {})):
                            continue
                        references.append(
                            Reference(
                                dep_name,
                                expression[4:] if expression.startswith("npm:") else expression,
                                dep_name + "@" + expression,
                                scope,
                                locator + "/" + field + "/" + npm_sources.pointer(dep_name),
                                optional,
                                not modern or scope == "peer" or expression.startswith("npm:"),
                            )
                        )
                packages.append(
                    Package(
                        located("record", [ordinal, keys]),
                        name,
                        version,
                        locator,
                        tuple(zip(keys, (expression for _name, expression in identities))),
                        tuple(references),
                        hashes,
                        source_key,
                    )
                )
            except InputRefusal as error:
                if (
                    "budget" in error.reason
                    or "deadline" in error.reason
                    or error.reason == "composition-check-budget-exceeded"
                ):
                    raise
                self.partial.add(error.reason)
        return Document(
            "unsupported" if self.partial else "parsed",
            sorted(self.partial)[0] if self.partial else "static-input",
            tuple(packages),
            blocked_descriptors=blocked,
        )


def parse(content, *, deadline, check, max_records=100000):
    if not callable(check) or type(max_records) is not int or not 0 <= max_records <= 100000:
        raise ValueError("trusted-yarn-parser-inputs-required")
    parser = Parser(deadline, check, max_records)
    try:
        if type(content) is not bytes:
            raise TypeError("exact-source-bytes-required")
        if len(content) > 2 * 1024 * 1024:
            raise InputRefusal("input-file-budget-exceeded")
        if re.match(rb"^(#.*(?:\r?\n))*?#\s+yarn\s+lockfile\s+v1\r?\n", content.removeprefix(b"\xef\xbb\xbf"), re.I):
            entries = yarn_legacy.parse(content, deadline=deadline, check=parser.step)
            return parser.parse_entries(entries, False)
        documents = load_documents(content, check=parser.step)
        if len(documents) != 1:
            raise InputRefusal("unsupported-yarn-document-count")
        data = documents[0]
        metadata = parser.mapping(data.get("__metadata"))
        if type(metadata.get("version")) is not str or metadata.get("version") not in {
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "10",
        }:
            raise InputRefusal("unsupported-yarn-lock-version")
        if set(metadata) - {"version", "cacheKey"}:
            parser.partial.add("unsupported-yarn-lock-metadata")
        entries = []
        for key, raw in data.items():
            parser.step()
            if key != "__metadata":
                entries.append((tuple(re.split(r", *", parser.text(key))), raw))
        return parser.parse_entries(entries, True)
    except InputRefusal as error:
        if error.reason == "composition-check-budget-exceeded":
            raise
        reason = error.reason
    except (ValueError, RecursionError, UnicodeError):
        reason = "invalid-yarn-source-syntax"
    return Document(
        (
            "bounded-omission"
            if "budget" in reason or "deadline" in reason
            else "unsupported" if reason.startswith("unsupported-") else "failed"
        ),
        reason,
    )
