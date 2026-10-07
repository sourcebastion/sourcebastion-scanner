"""Pinned registry-only Poetry, uv and PDM lock subsets, without resolution.

These adapters enumerate locked evidence. Group/marker selection is unknown;
Poetry uses its pinned maintained pure constraint parser. Unsupported source and
environment controls remain explicit refusals. uv edge markers are simplified relative to
root Python compatibility and are never used for activation/disjointness.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit, unquote

from packaging.utils import parse_wheel_filename, parse_sdist_filename
from packaging.version import Version

from .inputs import InputRefusal, relative_path
from .python_locks import LockParser, LockedPackage, MAX_EDGES
from .requirements import parse_requirement
from .poetry_constraints import constraint as poetry_constraint


class PythonLockParser(LockParser):
    def fields(self, value, allowed):
        value = self.mapping(value)
        if set(value) - set(allowed):
            raise InputRefusal("unsupported-lock-field")
        return value

    def sequence(self, value):
        self.check()
        if not isinstance(value, list):
            raise InputRefusal("invalid-lock-list")
        return value

    def content_hash(self, metadata, key, prefix=""):
        if key not in metadata:
            self.missing_metadata = True
            return
        value = self.text(metadata[key])
        if not re.fullmatch(re.escape(prefix) + r"[0-9a-fA-F]{64}", value):
            raise InputRefusal("invalid-lock-metadata-hash")

    def source(self, value):
        value = self.fields(value, {"registry"})
        if set(value) != {"registry"}:
            raise InputRefusal("unsupported-lock-package-source")
        self.url(value["registry"])
        # Internal selector binding only; output never retains the URI.
        return hashlib.sha256(value["registry"].encode()).hexdigest()

    def compatibility(self, value, locator):
        if value == "*":
            return
        super().compatibility(value, locator)

    def poetry_compatibility(self, value, locator):
        value = self.text(value)
        poetry_constraint(value)
        if value != "*":
            self.retain()
            self.environment.append((locator, value))

    def file(self, value, name, version, style):
        self.retain()
        value = self.fields(value, {"file", "hash"} if style == "poetry" else {"file", "url", "hash"})
        if ("file" in value) == ("url" in value):
            raise InputRefusal("invalid-lock-artifact-source")
        if "url" in value:
            self.url(value["url"])
            filename = unquote(urlsplit(value["url"]).path.rsplit("/", 1)[-1])
        else:
            filename = self.text(value["file"])
        self.filename(filename, name, version)
        return self.hashes([value.get("hash")])

    def filename(self, filename, name, version):
        filename = self.text(filename)
        if "/" in filename or relative_path(filename) != filename:
            raise InputRefusal("invalid-lock-artifact-name")
        if re.search(r"\d{129,}", filename):
            raise InputRefusal("requirement-complexity-budget-exceeded")
        try:
            parsed = parse_wheel_filename(filename) if filename.endswith(".whl") else parse_sdist_filename(filename)
        except ValueError:
            raise InputRefusal("invalid-lock-artifact-name") from None
        if parsed[0] != name or parsed[1] != Version(version):
            raise InputRefusal("conflicting-lock-artifact-identity")

    def files(self, value, name, version, style):
        hashes = set()
        for entry in self.sequence(value):
            hashes.update(self.file(entry, name, version, style))
        if not value:
            self.missing_source = True
        return tuple(sorted(hashes))

    def selector(
        self,
        name,
        requirement,
        locator,
        *,
        scope="unknown",
        marker=None,
        extras=(),
        source=None,
        dialect="pep440",
        exact_version=None,
    ):
        self.retain()
        self.edges += 1
        if self.edges > MAX_EDGES:
            raise InputRefusal("lock-edge-budget-exceeded")
        requirement = self.text(requirement)
        declared = requirement
        if requirement == "*":
            requirement = ""
        if dialect == "poetry-core-2.1.3":
            poetry_constraint(declared)
            selected_name, specifier = self.group(name), declared
        else:
            record = parse_requirement(0, self.group(name) + requirement)
            if (
                record.name != self.group(name)
                or record.direct_reference
                or record.marker
                or record.extras
                or record.hashes
            ):
                raise InputRefusal("unsupported-lock-dependency-selector")
            selected_name, specifier = record.name, record.specifier
        return tuple(
            {
                "name": selected_name,
                "specifier": specifier,
                "dialect": dialect,
                "declared_constraint": declared,
                "condition": marker,
                "extras": extras,
                "scope": scope,
                "locator": locator,
                "source": source,
                "exact_version": exact_version,
                "typed": True,
            }.items()
        )

    def poetry_dependencies(self, data, locator):
        dependencies = []
        names = set()
        for original, requirement in self.mapping(data).items():
            name = self.group(original)
            if name in names:
                raise InputRefusal("duplicate-lock-dependency")
            names.add(name)
            variants = requirement if isinstance(requirement, list) else [requirement]
            if not variants:
                raise InputRefusal("invalid-lock-dependency")
            for index, variant in enumerate(variants):
                path = locator + "." + original + (f"[{index}]" if isinstance(requirement, list) else "")
                marker, extras = None, ()
                if isinstance(variant, dict):
                    variant = self.fields(variant, {"version", "markers", "extras", "optional"})
                    marker = self.marker(variant["markers"]) if "markers" in variant else None
                    extras = self.names(variant.get("extras", []))
                    if "optional" in variant:
                        if type(variant["optional"]) is not bool:
                            raise InputRefusal("invalid-lock-optional")
                        if variant["optional"]:
                            raise InputRefusal("unsupported-lock-optional-dependency")
                    variant = variant.get("version", "*")
                dependencies.append(
                    self.selector(name, variant, path, marker=marker, extras=extras, dialect="poetry-core-2.1.3")
                )
        return tuple(dependencies)

    def poetry(self, data):
        data = self.fields(data, {"package", "metadata", "extras"})
        if self.mapping(data.get("extras", {})):
            raise InputRefusal("unsupported-lock-extras")
        meta = self.fields(data.get("metadata"), {"lock-version", "python-versions", "content-hash"})
        version = meta.get("lock-version")
        if version not in {"2.0", "2.1"}:
            raise InputRefusal("unsupported-poetry-version")
        self.content_hash(meta, "content-hash")
        self.poetry_compatibility(meta.get("python-versions"), "metadata.python-versions")
        for index, row in enumerate(self.sequence(data.get("package"))):
            row = self.fields(
                row,
                {
                    "name",
                    "version",
                    "description",
                    "optional",
                    "python-versions",
                    "files",
                    "groups",
                    "markers",
                    "dependencies",
                    "extras",
                    "source",
                    "develop",
                },
            )
            if self.mapping(row.get("extras", {})):
                raise InputRefusal("unsupported-lock-extras")
            if "source" in row or "develop" in row:
                raise InputRefusal("unsupported-lock-package-source")
            self.text(row.get("description", ""))
            if type(row.get("optional")) is not bool:
                raise InputRefusal("invalid-lock-optional")
            name, selected = self.group(row.get("name")), self.version(row.get("version"))
            locator = f"package[{index}]"
            compatibility = row.get("python-versions")
            self.poetry_compatibility(compatibility, locator + ".python-versions")
            hashes = self.files(row.get("files", []), name, selected, "poetry")
            dependencies = self.poetry_dependencies(row.get("dependencies", {}), locator + ".dependencies")
            groups = self.names(row.get("groups", []))
            if version == "2.0" and (groups or "markers" in row):
                raise InputRefusal("unsupported-lock-environment")
            if version == "2.1" and not groups:
                raise InputRefusal("invalid-lock-groups")
            markers = row.get("markers", "*")
            if isinstance(markers, dict) and set(markers) - set(row.get("groups", [])):
                raise InputRefusal("invalid-lock-group-marker")
            originals = row.get("groups", [])
            for ordinal, group in enumerate(groups or (None,)):
                raw = markers.get(originals[ordinal], "*") if isinstance(markers, dict) else markers
                marker = None if raw == "*" else self.marker(raw)
                self.add_package(
                    LockedPackage(
                        name,
                        selected,
                        locator if group is None else locator + f".groups[{ordinal}]",
                        scope="unknown" if group is None else "group:" + group,
                        marker=marker,
                        hashes=hashes,
                        requires_python=None if compatibility == "*" else compatibility,
                        dependencies=dependencies,
                        conditional=True,
                        entry=locator,
                        optional=row["optional"],
                        group=None if group is None else originals[ordinal],
                    )
                )

    def pdm(self, data):
        data = self.fields(data, {"metadata", "package"})
        meta = self.fields(data.get("metadata"), {"lock_version", "groups", "strategy", "targets", "content_hash"})
        if meta.get("lock_version") != "4.5.0":
            raise InputRefusal("unsupported-pdm-version")
        self.content_hash(meta, "content_hash", "sha256:")
        groups = self.names(meta.get("groups"))
        strategy = self.sequence(meta.get("strategy"))
        if any(not isinstance(flag, str) for flag in strategy):
            raise InputRefusal("invalid-lock-strategy")
        if len(set(strategy)) != len(strategy) or set(strategy) - {
            "inherit_metadata",
            "cross_platform",
            "static_urls",
            "direct_minimal_versions",
        }:
            raise InputRefusal("unsupported-lock-strategy")
        if "inherit_metadata" not in strategy:
            raise InputRefusal("unsupported-lock-inherited-environment")
        for index, target in enumerate(self.sequence(meta.get("targets", []))):
            self.retain()
            target = self.fields(target, {"requires_python"})
            if "requires_python" in target:
                self.compatibility(target["requires_python"], f"metadata.targets[{index}].requires_python")
        for index, row in enumerate(self.sequence(data.get("package"))):
            row = self.fields(
                row,
                {
                    "name",
                    "version",
                    "requires_python",
                    "groups",
                    "marker",
                    "extras",
                    "summary",
                    "files",
                    "dependencies",
                },
            )
            name, selected = self.group(row.get("name")), self.version(row.get("version"))
            locator = f"package[{index}]"
            self.text(row.get("summary", ""))
            compatibility = row.get("requires_python")
            if compatibility is not None:
                self.compatibility(compatibility, locator + ".requires_python")
            package_groups = self.names(row.get("groups"))
            if not package_groups or set(package_groups) - set(groups):
                raise InputRefusal("invalid-lock-groups")
            marker = self.marker(row["marker"]) if "marker" in row else None
            extras = tuple(sorted(self.names(row.get("extras", []))))
            files = self.sequence(row.get("files", []))
            if "static_urls" not in strategy and any("url" in self.mapping(item) for item in files):
                raise InputRefusal("unsupported-lock-static-url")
            hashes = self.files(files, name, selected, "pdm")
            dependencies = []
            for dep_index, raw in enumerate(self.sequence(row.get("dependencies", []))):
                requirement = parse_requirement(0, self.text(raw))
                if requirement.direct_reference or requirement.hashes:
                    raise InputRefusal("unsupported-lock-dependency-selector")
                self.retain(len(requirement.extras))
                dependencies.append(
                    self.selector(
                        requirement.name,
                        requirement.specifier,
                        f"{locator}.dependencies[{dep_index}]",
                        marker=requirement.marker,
                        extras=requirement.extras,
                    )
                )
            for ordinal, group in enumerate(package_groups):
                self.add_package(
                    LockedPackage(
                        name,
                        selected,
                        locator + f".groups[{ordinal}]",
                        scope="group:" + group,
                        marker=marker,
                        extras=extras,
                        hashes=hashes,
                        requires_python=compatibility,
                        dependencies=tuple(dependencies),
                        conditional=True,
                        entry=locator,
                        group=row["groups"][ordinal],
                    )
                )

    def uv_artifact(self, value, name, version, kind):
        self.retain()
        value = self.fields(value, {"url", "hash", "size"})
        # The pinned subset does not discard upload-time/zstd/local source fields.
        self.url(value.get("url"))
        hashes = self.hashes([value.get("hash")])
        if "size" in value and (type(value["size"]) is not int or not 0 <= value["size"] < 2**64):
            raise InputRefusal("invalid-lock-artifact-size")
        filename = self.text(unquote(urlsplit(value["url"]).path.rsplit("/", 1)[-1]))
        if "/" in filename or relative_path(filename) != filename:
            raise InputRefusal("invalid-lock-artifact-name")
        if re.search(r"\d{129,}", filename):
            raise InputRefusal("requirement-complexity-budget-exceeded")
        if kind == "wheel":
            try:
                parsed = parse_wheel_filename(filename)
            except ValueError:
                raise InputRefusal("invalid-lock-artifact-name") from None
            selected = Version(version)
            if parsed[0] != name or (parsed[1] != selected and Version(parsed[1].public) != selected):
                raise InputRefusal("conflicting-lock-artifact-identity")
        # UV permits arbitrary sdist names (e.g. source.zip). Their filename
        # does not corroborate package identity. The lock pin remains asserted.
        return hashes

    def uv(self, data):
        data = self.fields(
            data,
            {
                "version",
                "revision",
                "requires-python",
                "resolution-markers",
                "supported-markers",
                "required-markers",
                "conflicts",
                "options",
                "manifest",
                "package",
            },
        )
        if (
            type(data.get("version")) is not int
            or data["version"] != 1
            or type(data.get("revision")) is not int
            or data["revision"] != 3
        ):
            raise InputRefusal("unsupported-uv-version")
        self.compatibility(data.get("requires-python"), "requires-python")
        for field in ("resolution-markers", "supported-markers", "required-markers", "conflicts"):
            if self.sequence(data.get(field, [])):
                raise InputRefusal("unsupported-lock-environment")
        for field in ("options", "manifest"):
            if self.mapping(data.get(field, {})):
                raise InputRefusal("unsupported-lock-resolver-control")
        for index, row in enumerate(self.sequence(data.get("package"))):
            row = self.fields(
                row,
                {
                    "name",
                    "version",
                    "source",
                    "sdist",
                    "wheels",
                    "resolution-markers",
                    "dependencies",
                    "optional-dependencies",
                    "dev-dependencies",
                    "dependency-groups",
                    "metadata",
                },
            )
            name, selected = self.group(row.get("name")), self.version(row.get("version"))
            source_key = self.source(row.get("source"))
            locator = f"package[{index}]"
            if self.sequence(row.get("resolution-markers", [])):
                raise InputRefusal("unsupported-lock-environment")
            for field in ("optional-dependencies", "dev-dependencies", "dependency-groups", "metadata"):
                if self.mapping(row.get(field, {})):
                    raise InputRefusal("unsupported-lock-environment")
            hashes = set()
            for wheel in self.sequence(row.get("wheels", [])):
                hashes.update(self.uv_artifact(wheel, name, selected, "wheel"))
            if "sdist" in row:
                hashes.update(self.uv_artifact(row["sdist"], name, selected, "sdist"))
            if not hashes:
                self.missing_source = True
            dependencies = []
            for dep_index, dependency in enumerate(self.sequence(row.get("dependencies", []))):
                dependency = self.fields(dependency, {"name", "version", "source", "marker", "extra"})
                version = self.version(dependency["version"]) if "version" in dependency else None
                source = self.source(dependency["source"]) if "source" in dependency else None
                marker = self.marker(dependency["marker"]) if "marker" in dependency else None
                extras = self.names(dependency.get("extra", []))
                dependencies.append(
                    self.selector(
                        dependency.get("name"),
                        "==" + version if version else "",
                        f"{locator}.dependencies[{dep_index}]",
                        marker=marker,
                        extras=extras,
                        source=source,
                        exact_version=version,
                    )
                )
            self.add_package(
                LockedPackage(
                    name,
                    selected,
                    locator,
                    hashes=tuple(sorted(hashes)),
                    dependencies=tuple(dependencies),
                    conditional=True,
                    source_key=source_key,
                    entry=locator,
                )
            )
