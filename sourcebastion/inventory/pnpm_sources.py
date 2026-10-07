"""Registry pnpm9 facts retaining every document and snapshot context.

Package/importer references are source-selected keys, never equal-purl joins.
Unsupported workspace, patch and resolver contexts remain partial.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re

from .bounded_yaml import load_documents
from .inputs import InputRefusal, relative_path
from .npm_sources import Parser as NpmParser

VERSION = "sourcebastion.pnpm-sources/1"
FIELDS = {
    "dependencies": "runtime",
    "devDependencies": "development",
    "optionalDependencies": "optional",
    "configDependencies": "build",
    "packageManagerDependencies": "tooling",
}


def located(kind, key):
    # Lock keys may contain private URLs/protocol identifiers. An opaque locator
    # binds the exact source key without publishing it; the file hash is retained.
    return kind + ":sha256:" + hashlib.sha256(key.encode()).hexdigest()


@dataclass(frozen=True)
class Reference:
    name: str
    selected: str | None
    declared_range: str | None
    scope: str
    locator: str
    reason: str | None = None


@dataclass(frozen=True)
class Package:
    key: str
    name: str
    version: str
    locator: str
    references: tuple = ()
    hashes: tuple = ()
    source_key: str | None = None
    optional: bool | None = None
    # Opaque source-selected peer context, not an installed environment.
    peer_context_sha256: str | None = None


@dataclass(frozen=True)
class Importer:
    key: str
    locator: str
    references: tuple


@dataclass(frozen=True)
class Document:
    ordinal: int
    disposition: str
    reason: str
    packages: tuple = ()
    importers: tuple = ()


@dataclass(frozen=True)
class Result:
    disposition: str
    reason: str
    documents: tuple = ()
    parser: str = VERSION


class Parser(NpmParser):
    def identity(self, key):
        key = self.text(key)
        # Snapshot context is retained by exact key hash, never interpreted as
        # this host's platform or peer selection. No parenthesis flattening joins.
        base, separator, context = key.partition("(")
        match = re.fullmatch(r"(@[^/]+/[^@]+|[^@/]+)@(.+)", base)
        if not match:
            raise InputRefusal("unsupported-pnpm-package-identity")
        name, version = self.name(match[1]), self.version(match[2])
        if separator and (not context.endswith(")") or context.count("(") + 1 != context.count(")")):
            raise InputRefusal("unsupported-pnpm-peer-context")
        return base, name, version, hashlib.sha256((separator + context).encode()).hexdigest() if separator else None

    def boolean(self, value):
        if type(value) is not str or value not in {"true", "false"}:
            raise InputRefusal("invalid-pnpm-boolean")
        return value == "true"

    def reference(self, name, selected, declared, scope, locator):
        self.retain()
        name = self.name(name)
        selected = self.text(selected)
        declared = self.text(declared, empty=True) if declared is not None else None
        try:
            self.identity(name + "@" + selected)
            reason = None
        except InputRefusal as error:
            if (
                "budget" in error.reason
                or "deadline" in error.reason
                or error.reason == "composition-check-budget-exceeded"
            ):
                raise
            selected, reason = None, "unsupported-pnpm-reference"
            self.partial.add(reason)
        return Reference(name, selected, declared, scope, locator, reason)

    def document(self, data, ordinal):
        self.partial = set()
        if data.get("lockfileVersion") != "9.0":
            raise InputRefusal("unsupported-pnpm-lock-version")
        known = {
            "lockfileVersion",
            "settings",
            "importers",
            "packages",
            "snapshots",
            "time",
            "catalogs",
            "ignoredOptionalDependencies",
            "neverBuiltDependencies",
            "onlyBuiltDependencies",
            "overrides",
            "packageExtensionsChecksum",
            "patchedDependencies",
            "pnpmfileChecksum",
            "untrackedPnpmfileReadPackageHook",
        }
        if set(data) - known:
            self.partial.add("unsupported-pnpm-document-controls")
        for key in (
            "catalogs",
            "ignoredOptionalDependencies",
            "overrides",
            "packageExtensionsChecksum",
            "patchedDependencies",
            "pnpmfileChecksum",
            "untrackedPnpmfileReadPackageHook",
        ):
            if key in data:
                self.partial.add("unsupported-pnpm-selection-controls")
        settings = self.mapping(data.get("settings", {}))
        for key, value in settings.items():
            self.step()
            if key in {"autoInstallPeers", "dedupePeers", "excludeLinksFromLockfile", "injectWorkspacePackages"}:
                self.boolean(value)
            else:
                self.partial.add("unsupported-pnpm-selection-controls")
        prefix = "documents[" + str(ordinal) + "]/"
        records, base_rows = {}, {}
        for key, raw in self.mapping(data.get("packages", {})).items():
            self.retain()
            try:
                base, name, version, context = self.identity(key)
                if context is not None:
                    raise InputRefusal("unsupported-pnpm-package-table-context")
                raw = self.mapping(raw)
                known_package = {
                    "resolution",
                    "name",
                    "version",
                    "id",
                    "hasBin",
                    "engines",
                    "os",
                    "cpu",
                    "libc",
                    "peerDependencies",
                    "peerDependenciesMeta",
                    "bundledDependencies",
                    "deprecated",
                    "patched",
                }
                if set(raw) - known_package:
                    self.partial.add("unsupported-pnpm-package-controls")
                if "name" in raw and raw["name"] != name or "version" in raw and raw["version"] != version:
                    raise InputRefusal("unsupported-pnpm-nonregistry-package")
                resolution = self.mapping(raw.get("resolution", {}))
                if not {"integrity", "tarball"}.intersection(resolution):
                    # The key still observes name/version, but a fragment is
                    # not a complete registry/tarball resolution record.
                    self.partial.add("incomplete-pnpm-package-resolution")
                if set(resolution) - {"integrity", "tarball", "revision"}:
                    raise InputRefusal("unsupported-pnpm-package-source")
                if "revision" in resolution and (
                    type(resolution["revision"]) is not str
                    or not re.fullmatch(r"0|[1-9][0-9]{0,8}", resolution["revision"])
                ):
                    raise InputRefusal("unsupported-pnpm-registry-revision")
                hashes = self.hashes(resolution["integrity"]) if "integrity" in resolution else ()
                source_key = self.source(resolution["tarball"]) if "tarball" in resolution else None
                if any(key in raw for key in ("engines", "os", "cpu", "libc", "bundledDependencies", "patched")):
                    self.partial.add("unsupported-pnpm-package-selection-controls")
                for peer_name, peer_range in self.mapping(raw.get("peerDependencies", {})).items():
                    self.name(peer_name)
                    self.text(peer_range, empty=True)
                    self.partial.add("unassessed-pnpm-peer-conditions")
                if "peerDependenciesMeta" in raw:
                    self.mapping(raw["peerDependenciesMeta"])
                    self.partial.add("unassessed-pnpm-peer-conditions")
                base_rows[base] = (name, version, hashes, source_key)
            except InputRefusal as error:
                if (
                    "budget" in error.reason
                    or "deadline" in error.reason
                    or error.reason == "composition-check-budget-exceeded"
                ):
                    raise
                self.partial.add(error.reason)
        used_bases = set()
        for key, raw in self.mapping(data.get("snapshots", {})).items():
            self.retain()
            try:
                base, name, version, context = self.identity(key)
                if base not in base_rows:
                    raise InputRefusal("unbound-pnpm-snapshot-package")
                raw = self.mapping(raw)
                if set(raw) - {"dependencies", "optionalDependencies", "optional", "transitivePeerDependencies"}:
                    self.partial.add("unsupported-pnpm-snapshot-controls")
                references = []
                locator = prefix + located("snapshot", key)
                for field, scope in (("dependencies", "runtime"), ("optionalDependencies", "optional")):
                    for dep_name, selected in self.mapping(raw.get(field, {})).items():
                        ref_loc = locator + "/" + field + "/" + dep_name
                        references.append(self.reference(dep_name, selected, None, scope, ref_loc))
                optional = self.boolean(raw["optional"]) if "optional" in raw else None
                if "transitivePeerDependencies" in raw:
                    values = raw["transitivePeerDependencies"]
                    if type(values) is not list:
                        raise InputRefusal("invalid-pnpm-peer-list")
                    for name_in_peer in values:
                        self.name(name_in_peer)
                    self.partial.add("unassessed-pnpm-peer-conditions")
                _, _, hashes, source_key = base_rows[base]
                records[key] = Package(
                    key, name, version, locator, tuple(references), hashes, source_key, optional, context
                )
                used_bases.add(base)
            except InputRefusal as error:
                if (
                    "budget" in error.reason
                    or "deadline" in error.reason
                    or error.reason == "composition-check-budget-exceeded"
                ):
                    raise
                self.partial.add(error.reason)
        # Package-table observations without snapshots remain separately located
        # and cannot become endpoints of snapshot-selected dependencies.
        for base, (name, version, hashes, source_key) in base_rows.items():
            self.step()
            if base not in used_bases:
                records["package-only:" + base] = Package(
                    "package-only:" + base,
                    name,
                    version,
                    prefix + located("package", base),
                    hashes=hashes,
                    source_key=source_key,
                )
                self.partial.add("missing-pnpm-snapshot")
        importers = []
        for key, raw in self.mapping(data.get("importers", {})).items():
            self.retain()
            if key != "." and relative_path(key) != key:
                raise InputRefusal("unsupported-pnpm-importer-path")
            raw = self.mapping(raw)
            if set(raw) - set(FIELDS) or "dependenciesMeta" in raw:
                self.partial.add("unsupported-pnpm-importer-controls")
            references = []
            locator = prefix + located("importer", key)
            for field, scope in FIELDS.items():
                for name, selection in self.mapping(raw.get(field, {})).items():
                    selection = self.mapping(selection)
                    if set(selection) != {"specifier", "version"}:
                        raise InputRefusal("unsupported-pnpm-importer-selector")
                    references.append(
                        self.reference(
                            name,
                            selection["version"],
                            selection["specifier"],
                            scope,
                            locator + "/" + field + "/" + name,
                        )
                    )
            importers.append(Importer(key, locator, tuple(references)))
        return Document(
            ordinal,
            "unsupported" if self.partial else "parsed",
            sorted(self.partial)[0] if self.partial else "static-input",
            tuple(records.values()),
            tuple(importers),
        )


def parse(content, *, deadline, check, max_records=100000):
    if type(max_records) is not int or not 0 <= max_records <= 100000 or not callable(check):
        raise ValueError("trusted-pnpm-parser-inputs-required")
    parser = Parser(deadline, check, max_records)
    try:
        documents = load_documents(content, check=parser.step)
        results = []
        for ordinal, data in enumerate(documents):
            try:
                results.append(parser.document(data, ordinal))
            except InputRefusal as error:
                if (
                    "budget" in error.reason
                    or "deadline" in error.reason
                    or error.reason == "composition-check-budget-exceeded"
                ):
                    raise
                results.append(
                    Document(
                        ordinal, "unsupported" if error.reason.startswith("unsupported-") else "failed", error.reason
                    )
                )
        parser.step()
        incomplete = [row for row in results if row.disposition != "parsed"]
        return Result(
            "unsupported" if incomplete else "parsed",
            incomplete[0].reason if incomplete else "static-input",
            tuple(results),
        )
    except InputRefusal as error:
        if error.reason == "composition-check-budget-exceeded":
            raise
        reason = error.reason
    return Result(
        (
            "bounded-omission"
            if "budget" in reason or "deadline" in reason
            else "unsupported" if reason.startswith("unsupported-") else "failed"
        ),
        reason,
    )
