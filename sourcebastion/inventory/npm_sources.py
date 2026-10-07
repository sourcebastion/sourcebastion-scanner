"""Bounded npm source facts, independent of project code and installation.

Supports static package.json and registry package-lock/shrinkwrap versions2/3.
Other source protocols and workspace/link contexts remain visible omissions.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import binascii
import hashlib
import json
import math
import re
import time
from urllib.parse import urlsplit

from .contract import package_purl
from .inputs import InputRefusal

VERSION = "sourcebastion.npm-sources/1"
FORMATS = frozenset({"npm-manifest", "npm-lock"})
FIELDS = {
    "dependencies": "runtime",
    "devDependencies": "development",
    "optionalDependencies": "optional",
    "peerDependencies": "peer",
}
NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*")


@dataclass(frozen=True)
class Selector:
    name: str
    expression: str
    scope: str
    locator: str
    optional: bool = False


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    entry: str
    locator: str
    selectors: tuple
    scopes: tuple
    hashes: tuple = ()
    source_key: str | None = None
    optional: bool | None = None


@dataclass(frozen=True)
class Document:
    disposition: str
    reason: str
    application: tuple | None = None
    declarations: tuple = ()
    packages: tuple = ()
    # All source entries, including refused ones, block ancestor fallback.
    entries: frozenset = frozenset()
    parser: str = VERSION


def pointer(value):
    return value.replace("~", "~0").replace("/", "~1")


class Parser:
    def __init__(self, deadline, check, max_records):
        self.deadline, self.shared_check, self.max_records = deadline, check, max_records
        self.records = 0
        self.partial = set()

    def step(self):
        self.shared_check()
        if time.monotonic() > self.deadline:
            raise InputRefusal("input-deadline-exceeded")

    def retain(self):
        self.step()
        if self.records >= self.max_records:
            raise InputRefusal("npm-source-record-budget-exceeded")
        self.records += 1

    def text(self, value, maximum=16384, empty=False):
        self.step()
        if (
            type(value) is not str
            or len(value) > maximum
            or (not empty and not value)
            or any(ord(c) < 32 or 127 <= ord(c) < 160 for c in value)
        ):
            raise InputRefusal("invalid-npm-source-text")
        return value

    def name(self, value):
        value = self.text(value, 214)
        if not NAME.fullmatch(value):
            raise InputRefusal("unsupported-npm-name")
        return value

    def version(self, value):
        value = self.text(value, 256)
        if re.search(r"[0-9]{129,}", value):
            raise InputRefusal("npm-source-complexity-budget-exceeded")
        try:
            package_purl("npm", "version-check", value)
        except ValueError:
            raise InputRefusal("unsupported-npm-selected-version") from None
        return value

    def mapping(self, value):
        self.step()
        if type(value) is not dict:
            raise InputRefusal("invalid-npm-source-table")
        return value

    def pairs(self, values):
        result = {}
        for key, value in values:
            self.step()
            if key in result:
                raise InputRefusal("duplicate-npm-source-key")
            result[key] = value
        return result

    def load(self, content):
        if type(content) is not bytes:
            raise TypeError("exact-source-bytes-required")
        if len(content) > 2 * 1024 * 1024:
            raise InputRefusal("input-file-budget-exceeded")
        text = content.decode("utf-8-sig")
        # Bound decoder nesting BEFORE allocation, including ignored metadata.
        depth, quoted, escape = 0, False, False
        for offset, char in enumerate(text):
            if offset % 512 == 0:
                self.step()
            if quoted:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                if depth > 32:
                    raise InputRefusal("npm-source-depth-budget-exceeded")
            elif char in "]}":
                depth -= 1

        def integer(value):
            self.step()
            if len(value) > 128:
                raise InputRefusal("npm-source-number-budget-exceeded")
            return int(value)

        def floating(value):
            self.step()
            result = float(value)
            if not math.isfinite(result):
                raise InputRefusal("invalid-npm-source-number")
            return result

        def constant(_):
            raise InputRefusal("invalid-npm-source-number")

        result = json.loads(
            text, object_pairs_hook=self.pairs, parse_int=integer, parse_float=floating, parse_constant=constant
        )
        # Lazy iterator frames charge every node/key without dense intermediates.
        stack = [iter((result,))]
        nodes = 0
        while stack:
            try:
                value = next(stack[-1])
            except StopIteration:
                stack.pop()
                continue
            self.step()
            nodes += 1
            if nodes > 2000000:
                raise InputRefusal("npm-source-node-budget-exceeded")
            if type(value) is dict:
                for key in value:
                    self.step()
                    nodes += 1
                    if nodes > 2000000:
                        raise InputRefusal("npm-source-node-budget-exceeded")
                stack.append(iter(value.values()))
            elif type(value) is list:
                stack.append(iter(value))
        return self.mapping(result)

    def selectors(self, data, locator):
        result = []
        metadata = self.mapping(data.get("peerDependenciesMeta", {}))
        for name, value in metadata.items():
            self.name(name)
            value = self.mapping(value)
            if set(value) - {"optional"} or type(value.get("optional", False)) is not bool:
                raise InputRefusal("unsupported-npm-peer-metadata")
            if name not in self.mapping(data.get("peerDependencies", {})):
                raise InputRefusal("unbound-npm-peer-metadata")
        for field, scope in FIELDS.items():
            for name, expression in self.mapping(data.get(field, {})).items():
                self.retain()
                name = self.name(name)
                expression = self.text(expression, empty=True)
                # npm optionalDependencies overrides dependencies by name.
                if field == "dependencies" and name in self.mapping(data.get("optionalDependencies", {})):
                    continue
                result.append(
                    Selector(
                        name,
                        expression,
                        scope,
                        locator + "/" + field + "/" + pointer(name),
                        field == "peerDependencies" and metadata.get(name, {}).get("optional", False),
                    )
                )
        return tuple(result)

    def application(self, data):
        if "name" not in data:
            return None
        name = self.name(data["name"])
        version = self.version(data["version"]) if "version" in data else None
        return name, version

    def controls(self, data):
        for key in (
            "pnpm",
            "dependenciesMeta",
            "installConfig",
            "acceptDependencies",
            "workspaces",
            "overrides",
            "resolutions",
            "bundledDependencies",
            "bundleDependencies",
            "os",
            "cpu",
            "libc",
            "engines",
            "devEngines",
            "packageManager",
        ):
            self.step()
            if key in data:
                self.partial.add("unsupported-npm-selection-controls")

    def module_name(self, entry):
        entry = self.text(entry, 4096)
        parts, position, name = entry.split("/"), 0, None
        while position < len(parts):
            self.step()
            if parts[position] != "node_modules" or position + 1 >= len(parts):
                raise InputRefusal("unsupported-npm-package-context")
            position += 1
            name = parts[position]
            position += 1
            if name.startswith("@"):
                if position >= len(parts):
                    raise InputRefusal("unsupported-npm-package-context")
                name += "/" + parts[position]
                position += 1
            self.name(name)
        return name

    def hashes(self, value):
        result = []
        for supplied in self.text(value).split():
            self.retain()
            match = re.fullmatch(r"(sha1|sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})", supplied)
            if not match:
                raise InputRefusal("unsupported-npm-integrity")
            try:
                decoded = base64.b64decode(match[2], validate=True)
            except binascii.Error:
                raise InputRefusal("invalid-npm-integrity") from None
            if (
                len(decoded) != {"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}[match[1]]
                or base64.b64encode(decoded).decode() != match[2]
            ):
                raise InputRefusal("invalid-npm-integrity")
            result.append((match[1], decoded.hex()))
        if not result:
            raise InputRefusal("invalid-npm-integrity")
        return tuple(sorted(set(result)))

    def source(self, value):
        value = self.text(value)
        try:
            parsed = urlsplit(value)
            if parsed.scheme not in {"https", "http"} or not parsed.hostname:
                raise InputRefusal("unsupported-npm-package-source")
            parsed.port
        except ValueError:
            raise InputRefusal("unsupported-npm-package-source") from None
        # Credentials and raw URLs never enter the canonical inventory.
        return hashlib.sha256(value.encode()).hexdigest()

    def manifest(self, data):
        self.controls(data)
        application = self.application(data)
        if application is None and not any(field in data for field in FIELDS):
            self.partial.add("unsupported-npm-dependency-evidence")
        return self.finish(application=application, declarations=self.selectors(data, ""))

    def lock(self, data):
        if type(data.get("lockfileVersion")) is not int or data["lockfileVersion"] not in {2, 3}:
            raise InputRefusal("unsupported-npm-lock-version")
        packages = self.mapping(data.get("packages"))
        root = self.mapping(packages.get("", {}))
        self.controls(root)
        application = self.application(root)
        # Top-level metadata does not substitute for an explicit root entry.
        for key in ("name", "version"):
            if key in root and key in data and data[key] != root[key]:
                raise InputRefusal("contradictory-npm-lock-application")
        declarations = self.selectors(root, "/packages/")
        retained = []
        for entry, value in packages.items():
            self.retain()
            if entry == "":
                continue
            try:
                name = self.module_name(entry)
                value = self.mapping(value)
                if value.get("link", False) is not False:
                    raise InputRefusal("unsupported-npm-linked-package")
                if "name" in value and self.name(value["name"]) != name:
                    raise InputRefusal("unsupported-npm-alias-package")
                version = self.version(value.get("version"))
                source_key = self.source(value["resolved"]) if "resolved" in value else None
                hashes = self.hashes(value["integrity"]) if "integrity" in value else ()
                for key in ("dev", "optional", "devOptional", "peer", "extraneous", "inBundle", "hasShrinkwrap"):
                    if key in value and type(value[key]) is not bool:
                        raise InputRefusal("invalid-npm-package-flag")
                if value.get("inBundle") or value.get("hasShrinkwrap"):
                    self.partial.add("unsupported-npm-nested-selection")
                if value.get("peer") or value.get("extraneous"):
                    self.partial.add("unsupported-npm-package-selection-context")
                self.controls(value)
                scopes = tuple(
                    key
                    for key, flag in (
                        ("development", value.get("dev", False) or value.get("devOptional", False)),
                        ("optional", value.get("optional", False) or value.get("devOptional", False)),
                    )
                    if flag
                ) or ("runtime",)
                if value.get("extraneous"):
                    scopes = ("unknown",)
                elif value.get("peer"):
                    scopes = ("peer",) + tuple(scope for scope in scopes if scope != "runtime")
                locator = "/packages/" + pointer(entry)
                retained.append(
                    Package(
                        name,
                        version,
                        entry,
                        locator,
                        self.selectors(value, locator),
                        scopes,
                        hashes,
                        source_key,
                        value.get("optional"),
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
        return self.finish(
            application=application,
            declarations=declarations,
            packages=tuple(retained),
            entries=frozenset(packages) - {""},
        )

    def finish(self, **values):
        self.step()
        return Document(
            "unsupported" if self.partial else "parsed",
            sorted(self.partial)[0] if self.partial else "static-input",
            **values,
        )


def parse(content, fmt, *, deadline, check, max_records=100000):
    if fmt not in FORMATS or not callable(check):
        raise ValueError("trusted-npm-source-parser-inputs-required")
    if type(max_records) is not int or not 0 <= max_records <= 100000:
        raise ValueError("invalid-npm-source-record-limit")
    parser = Parser(deadline, check, max_records)
    try:
        data = parser.load(content)
        return parser.manifest(data) if fmt == "npm-manifest" else parser.lock(data)
    except InputRefusal as error:
        if error.reason == "composition-check-budget-exceeded":
            raise
        reason = error.reason
    except (ValueError, RecursionError, UnicodeError):
        reason = "invalid-npm-source-syntax"
    disposition = (
        "bounded-omission"
        if "budget" in reason or "deadline" in reason
        else "unsupported" if reason.startswith("unsupported-") else "failed"
    )
    return Document(disposition, reason)
