"""Static Cargo source observations; no Cargo invocation or version resolver."""

from __future__ import annotations
from dataclasses import dataclass
import hashlib
import math
import re
import time
from urllib.parse import urlsplit

try:
    import tomllib
except ImportError:
    tomllib = None
from .contract import package_purl
from .inputs import InputRefusal

VERSION = "sourcebastion.cargo-sources/1"


@dataclass(frozen=True)
class Reference:
    name: str
    version: str | None
    source: str | None
    locator: str


@dataclass(frozen=True)
class Package:
    ordinal: int
    name: str
    version: str
    source: str | None
    admitted: bool
    dependencies: tuple = ()
    hashes: tuple = ()


@dataclass(frozen=True)
class Declaration:
    name: str
    expression: str | None
    locator: str
    scopes: tuple
    condition: str | None = None
    features: tuple = ()


@dataclass(frozen=True)
class Document:
    disposition: str
    reason: str
    packages: tuple = ()
    declarations: tuple = ()
    application: tuple | None = None
    parser: str = VERSION


class Parser:
    def __init__(self, deadline, check, maximum):
        self.deadline, self.shared_check, self.maximum = deadline, check, maximum
        self.count = 0
        self.partial = set()

    def step(self):
        self.shared_check()
        if time.monotonic() > self.deadline:
            raise InputRefusal("cargo-source-deadline-exceeded")

    def retain(self):
        self.step()
        if self.count >= self.maximum:
            raise InputRefusal("cargo-source-record-budget-exceeded")
        self.count += 1

    def text(self, value, maximum=16384, empty=False):
        self.step()
        if (
            type(value) is not str
            or len(value) > maximum
            or (not value and not empty)
            or any(ord(c) < 32 or 127 <= ord(c) < 160 or 0xD800 <= ord(c) <= 0xDFFF for c in value)
        ):
            raise InputRefusal("invalid-cargo-source-text")
        return value

    def name(self, value):
        value = self.text(value, 512)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", value):
            raise InputRefusal("unsupported-cargo-name")
        return value

    def version(self, value):
        value = self.text(value, 256)
        if re.search(r"[0-9]{129,}", value):
            raise InputRefusal("cargo-source-complexity-budget-exceeded")
        try:
            package_purl("cargo", "version-check", value)
        except ValueError:
            raise InputRefusal("unsupported-cargo-selected-version") from None
        return value

    def requirement(self, value):
        value = self.text(value)
        if not re.fullmatch(r"[A-Za-z0-9*^~<>=!., +_-]+", value):
            self.partial.add("unsupported-cargo-requirement-text")
            return None
        return value

    def feature(self, value):
        value = self.text(value, 512)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_+.-]*", value):
            raise InputRefusal("unsupported-cargo-feature-name")
        return value

    def mapping(self, value):
        self.step()
        if type(value) is not dict:
            raise InputRefusal("invalid-cargo-source-table")
        return value

    def sequence(self, value):
        self.step()
        if type(value) is not list:
            raise InputRefusal("invalid-cargo-source-list")
        return value

    def source(self, value):
        value = self.text(value)
        kind, separator, uri = value.partition("+")
        if not separator:
            raise InputRefusal("invalid-cargo-source-reference")
        # Public projection contains only the hash of this exact asserted URI.
        # No URL normalization can equate two source IDs for edge selection.
        try:
            parsed = urlsplit(uri)
            parsed.port
            registry = (
                kind in {"registry", "sparse"}
                and parsed.scheme in {"http", "https"}
                and bool(parsed.hostname)
                and parsed.username is None
                and parsed.password is None
                and not parsed.query
                and not parsed.fragment
            )
        except ValueError:
            raise InputRefusal("invalid-cargo-source-reference") from None
        return value, registry

    def reference(self, value, locator):
        self.retain()
        value = self.text(value)
        parts = value.split(" ", 2)
        name = self.name(parts[0])
        version = self.version(parts[1]) if len(parts) > 1 else None
        source = None
        if len(parts) > 2:
            if not parts[2].startswith("(") or not parts[2].endswith(")"):
                raise InputRefusal("invalid-cargo-lock-selector")
            source, _admitted = self.source(parts[2][1:-1])
        return Reference(name, version, source, locator)

    def lock(self, data):
        data = self.mapping(data)
        if type(data.get("version")) is not int or data["version"] not in {3, 4}:
            raise InputRefusal("unsupported-cargo-lock-version")
        if set(data) - {"version", "package", "patch", "metadata"}:
            self.partial.add("unsupported-cargo-lock-controls")
        if data.get("metadata"):
            self.partial.add("unsupported-cargo-lock-metadata")
        patches = self.mapping(data.get("patch", {}))
        if patches:
            self.partial.add("unassessed-cargo-unused-patches")
        packages = []
        identities = set()
        for ordinal, raw in enumerate(self.sequence(data.get("package", []))):
            self.retain()
            raw = self.mapping(raw)
            name, version = self.name(raw.get("name")), self.version(raw.get("version"))
            source, admitted = (None, False) if raw.get("source") is None else self.source(raw["source"])
            identity = (name, version, source)
            if identity in identities:
                self.partial.add("duplicate-cargo-lock-identity")
            identities.add(identity)
            if not admitted:
                self.partial.add("unsupported-cargo-nonregistry-identity")
            if "replace" in raw:
                self.partial.add("unsupported-cargo-replaced-package")
                admitted = False
            if set(raw) - {"name", "version", "source", "checksum", "dependencies", "replace"}:
                self.partial.add("unsupported-cargo-package-controls")
            hashes = ()
            if "checksum" in raw:
                checksum = self.text(raw["checksum"], 64)
                if not re.fullmatch(r"[a-f0-9]{64}", checksum):
                    raise InputRefusal("invalid-cargo-checksum")
                hashes = (("sha256", checksum),)
            refs = tuple(
                self.reference(value, f"package[{ordinal}].dependencies[{number}]")
                for number, value in enumerate(self.sequence(raw.get("dependencies", [])))
            )
            packages.append(Package(ordinal, name, version, source, admitted, refs, hashes))
        return Document(
            "unsupported" if self.partial else "parsed",
            sorted(self.partial)[0] if self.partial else "static-input",
            tuple(packages),
        )

    def manifest(self, data):
        data = self.mapping(data)
        application = None
        edition = "2015"
        if "package" in data:
            package = self.mapping(data["package"])
            edition = package.get("edition", "2015")
            if type(edition) is not str or edition not in {"2015", "2018", "2021", "2024"}:
                self.partial.add("unresolved-cargo-edition")
                edition = None
            name = self.name(package.get("name"))
            version = package.get("version")
            if type(version) is dict:
                self.partial.add("unresolved-cargo-workspace-version")
                version = None
            elif version is not None:
                version = self.version(version)
            application = (name, version)
        if "workspace" in data:
            self.mapping(data["workspace"])
            self.partial.add("unresolved-cargo-workspace-inheritance")
        if any(key in data for key in ("patch", "replace")):
            self.partial.add("unassessed-cargo-manifest-overrides")
        declarations = []

        def dependencies(table, prefix, scope, condition=None):
            for local_name, raw in self.mapping(table).items():
                self.retain()
                local_name = self.name(local_name)
                name, expression, features, optional = local_name, None, (), False
                if type(raw) is str:
                    expression = self.requirement(raw)
                else:
                    raw = self.mapping(raw)
                    if "package" in raw:
                        name = self.name(raw["package"])
                    if "version" in raw:
                        expression = self.requirement(raw["version"])
                    if "features" in raw:
                        features = tuple(self.feature(value) for value in self.sequence(raw["features"]))
                        if len(features) > 256:
                            raise InputRefusal("cargo-source-record-budget-exceeded")
                    for flag in ("optional", "default-features", "workspace", "public"):
                        if flag in raw and type(raw[flag]) is not bool:
                            raise InputRefusal("invalid-cargo-manifest-boolean")
                    optional = raw.get("optional", False)
                    if set(raw) - {"package", "version", "features", "optional", "default-features"}:
                        self.partial.add("unresolved-cargo-dependency-source-or-inheritance")
                # Ranges remain source declarations. No npm/Python grammar or
                # guessed floor version may resolve a Cargo manifest requirement.
                self.partial.add("unresolved-cargo-manifest-requirement")
                declarations.append(
                    Declaration(
                        name,
                        expression,
                        prefix + "." + local_name,
                        (scope, "optional") if optional else (scope,),
                        condition,
                        features,
                    )
                )

        fields = (
            ("dependencies", None, "runtime"),
            ("dev-dependencies", "dev_dependencies", "dev"),
            ("build-dependencies", "build_dependencies", "build"),
        )

        def dependency_tables(tables, prefix="", condition=None):
            for field, legacy, scope in fields:
                if legacy is not None and legacy in tables:
                    # Cargo's accessor prefers the hyphenated spelling. Retain
                    # the ignored spelling as a coverage uncertainty, never as
                    # a second independent dependency table.
                    self.mapping(tables[legacy])
                    if edition == "2024":
                        self.partial.add("unsupported-cargo-legacy-table-edition")
                    elif field in tables:
                        self.partial.add("unassessed-cargo-ignored-legacy-table")
                    else:
                        dependencies(tables[legacy], prefix + legacy, scope, condition)
                if field in tables:
                    dependencies(tables[field], prefix + field, scope, condition)

        dependency_tables(data)
        for condition, targets in self.mapping(data.get("target", {})).items():
            condition = self.text(condition)
            if not re.fullmatch(r'[A-Za-z0-9_-]+|cfg\([A-Za-z0-9_()= ,".\-]+\)', condition):
                raise InputRefusal("unsupported-cargo-target-expression")
            targets = self.mapping(targets)
            if set(targets) - {
                "dependencies",
                "dev-dependencies",
                "build-dependencies",
                "dev_dependencies",
                "build_dependencies",
            }:
                self.partial.add("unsupported-cargo-target-controls")
            dependency_tables(
                targets, "target:sha256:" + hashlib.sha256(condition.encode()).hexdigest() + ".", condition
            )
        if application is None and "workspace" not in data:
            self.partial.add("missing-cargo-project-identity")
        return Document(
            "unsupported" if self.partial else "parsed",
            sorted(self.partial)[0] if self.partial else "static-input",
            declarations=tuple(declarations),
            application=application,
        )


def parse(content, fmt, *, deadline, check, max_records=100000):
    if type(content) is not bytes or not callable(check):
        raise TypeError("trusted-cargo-parser-inputs-required")
    if type(max_records) is not int or not 0 <= max_records <= 100000:
        raise ValueError("invalid-cargo-record-limit")
    if type(deadline) not in {int, float} or not math.isfinite(deadline):
        raise ValueError("invalid-controller-deadline")
    if fmt not in {"cargo-lock", "cargo-manifest"}:
        raise ValueError("unsupported-cargo-input-format")
    parser = Parser(deadline, check, max_records)
    try:
        parser.step()
        if len(content) > 2 * 1024 * 1024:
            raise InputRefusal("input-file-budget-exceeded")
        if tomllib is None:
            raise InputRefusal("unsupported-toml-runtime")
        text = content.decode("utf-8-sig")
        # Bound explicit array/inline-table nesting before the stdlib decoder.
        # Quoted strings/comments are handled by the TOML lexer, not by regexp.
        depth = 0
        quote = None
        triple = False
        escape = False
        comment = False
        index = 0
        while index < len(text):
            if index % 512 == 0:
                parser.step()
            char = text[index]
            if comment:
                if char in "\r\n":
                    comment = False
            elif quote:
                if escape:
                    escape = False
                elif char == "\\" and quote == '"':
                    escape = True
                elif triple and text[index : index + 3] == quote * 3:
                    run = 3
                    while index + run < len(text) and text[index + run] == quote:
                        run += 1
                    quote = None
                    triple = False
                    index += run - 1
                elif not triple and char == quote:
                    quote = None
            elif char == "#":
                comment = True
            elif char in "\"'":
                quote = char
                triple = text[index : index + 3] == char * 3
                if triple:
                    index += 2
            elif char in "[{":
                depth += 1
                if depth > 32:
                    raise InputRefusal("cargo-toml-depth-budget-exceeded")
            elif char in "]}":
                depth -= 1
            index += 1
        data = tomllib.loads(text)
        pending = [(data, 0)]
        nodes = 0
        while pending:
            parser.step()
            value, nesting = pending.pop()
            nodes += 1
            if nodes > 2000000 or nesting > 32:
                raise InputRefusal("cargo-toml-structure-budget-exceeded")
            if type(value) is dict:
                pending.extend((child, nesting + 1) for child in value.values())
            elif type(value) is list:
                pending.extend((child, nesting + 1) for child in value)
        return parser.lock(data) if fmt == "cargo-lock" else parser.manifest(data)
    except InputRefusal as error:
        if error.reason == "composition-check-budget-exceeded":
            raise
        reason = error.reason
    except (ValueError, UnicodeError, RecursionError):
        reason = "invalid-cargo-source-syntax"
    return Document(
        (
            "bounded-omission"
            if "budget" in reason or "deadline" in reason
            else "unsupported" if reason.startswith("unsupported-") else "failed"
        ),
        reason,
    )
