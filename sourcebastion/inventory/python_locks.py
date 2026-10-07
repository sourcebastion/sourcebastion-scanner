"""Bounded typed lock enumeration; no resolver, installation or source access."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import time

try:
    import tomllib
except ImportError:
    tomllib = None
from urllib.parse import urlsplit, unquote

from packaging.version import Version
from packaging.utils import parse_wheel_filename, parse_sdist_filename

from .inputs import InputRefusal, relative_path
from .python_manifests import Parser, MAX_RECORDS
from .requirements import parse_requirement

VERSION = "sourcebastion.python-locks/1"
FORMATS = {
    "python-pipfile-lock": "pipfile-lock",
    "python-pylock": "pylock",
    "python-poetry-lock": "poetry-lock",
    "python-uv-lock": "uv-lock",
    "python-pdm-lock": "pdm-lock",
}
MAX_EDGES = 100000
HASH = re.compile(r"(?:sha256:[0-9a-fA-F]{64}|sha512:[0-9a-fA-F]{128})")


@dataclass(frozen=True)
class LockedPackage:
    name: str
    version: str
    locator: str
    scope: str = "unknown"
    marker: str | None = None
    extras: tuple = ()
    hashes: tuple = ()
    declared_range: str | None = None
    requires_python: str | None = None
    dependencies: tuple = ()
    # Additional lock adapters retain unresolved installation/group selection.
    conditional: bool = False
    source_key: str | None = None
    entry: str | None = None
    optional: bool | None = None
    group: str | None = None


@dataclass(frozen=True)
class Lock:
    path: str
    format: str
    sha256: str
    disposition: str
    reason: str
    packages: tuple = ()
    environment: tuple = ()
    record_count: int = 0
    parser: str = VERSION


class LockParser(Parser):
    def __init__(self, deadline, max_records):
        super().__init__(deadline, max_records)
        self.packages = []
        self.edges = 0
        self.missing_source = False
        self.missing_metadata = False
        self.record_count = 0

    def check(self):
        super().check()
        if getattr(self, "shared_check", None) is not None:
            self.shared_check()

    def retain(self, count=1):
        self.check()
        if self.record_count + count > self.max_records:
            raise InputRefusal("lock-record-budget-exceeded")
        self.record_count += count

    def compatibility(self, value, locator):
        self.retain()
        super().compatibility(value, locator)

    def mapping(self, value):
        self.check()
        if not isinstance(value, dict):
            raise InputRefusal("invalid-lock-table")
        return value

    def names(self, value):
        if not isinstance(value, list):
            raise InputRefusal("invalid-lock-list")
        self.retain(len(value))
        names = [self.group(name) for name in value]
        if len(set(names)) != len(names):
            raise InputRefusal("duplicate-lock-name")
        return tuple(names)

    def version(self, value):
        value = self.text(value)
        if re.search(r"\d{129,}", value):
            raise InputRefusal("requirement-complexity-budget-exceeded")
        try:
            Version(value)
        except ValueError:
            raise InputRefusal("invalid-lock-version") from None
        return value

    def marker(self, value):
        # This uses the bounded PEP508 parser and retains activation as unknown;
        # it never evaluates a marker against this evaluator's environment.
        return parse_requirement(0, "m046-marker; " + self.text(value)).marker

    def hashes(self, value):
        if not isinstance(value, list):
            raise InputRefusal("invalid-lock-hashes")
        result = []
        for entry in value:
            self.check()
            entry = self.text(entry)
            if not HASH.fullmatch(entry):
                raise InputRefusal("unsupported-lock-hash")
            self.retain()
            result.append(entry.lower())
        return tuple(sorted(set(result)))

    def url(self, value):
        value = self.text(value)
        try:
            parsed = urlsplit(value)
            if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
                raise InputRefusal("unsupported-lock-source-reference")
            if parsed.scheme not in {"https", "http"} or not parsed.hostname:
                raise InputRefusal("unsupported-lock-source-reference")
            parsed.port
        except ValueError:
            raise InputRefusal("invalid-lock-source") from None
        # No URI or credential payload is retained in an inventory record.

    def add_package(self, package):
        self.check()
        self.retain()
        self.packages.append(package)

    def pipfile(self, data):
        data = self.mapping(data)
        metadata = self.mapping(data.get("_meta"))
        if type(metadata.get("pipfile-spec")) is not int or metadata["pipfile-spec"] != 6:
            raise InputRefusal("unsupported-pipfile-version")
        if any(key not in {"pipfile-spec", "hash", "requires", "sources"} for key in metadata):
            raise InputRefusal("unsupported-lock-metadata")
        self.missing_metadata = not {"hash", "requires", "sources"}.issubset(metadata)
        if "hash" in metadata:
            supplied = self.mapping(metadata["hash"])
            if (
                set(supplied) != {"sha256"}
                or not isinstance(supplied["sha256"], str)
                or not re.fullmatch(r"[0-9a-fA-F]{64}", supplied["sha256"])
            ):
                raise InputRefusal("invalid-lock-metadata-hash")
        requires = self.mapping(metadata.get("requires", {}))
        for key, value in requires.items():
            if key not in {"python_version", "python_full_version"}:
                raise InputRefusal("unsupported-lock-environment")
            version = self.version(value)
            if key == "python_version":
                if not re.fullmatch(r"\d+\.\d+", version):
                    raise InputRefusal("invalid-lock-python-version")
                version += ".*"
            self.compatibility("==" + version, "/_meta/requires/" + key)
        sources = metadata.get("sources", [])
        if not isinstance(sources, list):
            raise InputRefusal("invalid-lock-list")
        source_names = set()
        for source in sources:
            source = self.mapping(source)
            if any(key not in {"name", "url", "verify_ssl"} for key in source):
                raise InputRefusal("unsupported-lock-source")
            name = self.text(source.get("name"))
            if name in source_names:
                raise InputRefusal("duplicate-lock-source")
            source_names.add(name)
            self.url(source.get("url"))
            if "verify_ssl" in source and type(source["verify_ssl"]) is not bool:
                raise InputRefusal("invalid-lock-source")
        groups = set()
        for original, packages in data.items():
            if original == "_meta":
                continue
            group = self.group(original)
            if group in groups:
                raise InputRefusal("duplicate-lock-group")
            groups.add(group)
            packages = self.mapping(packages)
            names = set()
            for original_name, fields in packages.items():
                self.check()
                name = self.group(original_name)
                if name in names:
                    raise InputRefusal("duplicate-lock-package")
                names.add(name)
                fields = self.mapping(fields)
                if any(key not in {"version", "markers", "extras", "hashes", "index"} for key in fields):
                    raise InputRefusal("unsupported-lock-package-source")
                declared = self.text(fields.get("version"))
                if not declared.startswith("=="):
                    raise InputRefusal("unselected-lock-version")
                version = self.version(declared[2:])
                marker = self.marker(fields["markers"]) if "markers" in fields else None
                extras = self.names(fields.get("extras", []))
                hashes = self.hashes(fields.get("hashes", []))
                if not hashes:
                    self.missing_source = True
                if "index" in fields and self.text(fields["index"]) not in source_names:
                    raise InputRefusal("unknown-lock-source")
                locator = "/" + original.replace("~", "~0").replace("/", "~1") + "/" + original_name
                scope = (
                    "development"
                    if original == "develop"
                    else ("unknown" if original == "default" else "group:" + group)
                )
                self.add_package(LockedPackage(name, version, locator, scope, marker, extras, hashes, declared))

    def artifact(self, value, package_name, package_version, kind):
        self.retain()
        value = self.mapping(value)
        if any(key not in {"name", "url", "path", "size", "upload-time", "hashes"} for key in value):
            raise InputRefusal("unsupported-lock-artifact")
        if not {"url", "path"}.intersection(value):
            raise InputRefusal("invalid-lock-artifact-source")
        if "url" in value:
            self.url(value["url"])
        if "path" in value:
            relative_path(self.text(value["path"]))
        name = (
            self.text(value["name"])
            if "name" in value
            else (
                value["path"].rsplit("/", 1)[-1]
                if "path" in value
                else unquote(urlsplit(value["url"]).path.rsplit("/", 1)[-1])
            )
        )
        if name != relative_path(name) or "/" in name:
            raise InputRefusal("invalid-lock-artifact-name")
        if re.search(r"\d{129,}", name):
            raise InputRefusal("requirement-complexity-budget-exceeded")
        try:
            parsed = parse_wheel_filename(name) if kind == "wheel" else parse_sdist_filename(name)
        except ValueError:
            raise InputRefusal("invalid-lock-artifact-name") from None
        if parsed[0] != package_name or parsed[1] != Version(package_version):
            raise InputRefusal("conflicting-lock-artifact-identity")
        if "size" in value and (type(value["size"]) is not int or not 0 <= value["size"] < 2**63):
            raise InputRefusal("invalid-lock-artifact-size")
        if "upload-time" in value:
            # This subset does not interpret date metadata or discard it while
            # claiming full typed admission.
            raise InputRefusal("unsupported-lock-artifact-time")
        hashes = self.mapping(value.get("hashes"))
        if not hashes:
            raise InputRefusal("invalid-lock-hashes")
        return self.hashes([algorithm + ":" + self.text(digest) for algorithm, digest in hashes.items()])

    def pylock(self, data):
        allowed = {
            "lock-version",
            "created-by",
            "packages",
            "requires-python",
            "environments",
            "extras",
            "dependency-groups",
            "default-groups",
            "tool",
        }
        if any(key not in allowed for key in data):
            raise InputRefusal("unsupported-lock-metadata")
        if data.get("lock-version") != "1.0":
            raise InputRefusal("unsupported-pylock-version")
        self.text(data.get("created-by"))
        for field in ("environments", "extras", "dependency-groups", "default-groups"):
            values = data.get(field, [])
            if not isinstance(values, list):
                raise InputRefusal("invalid-lock-list")
            if values:
                raise InputRefusal("unsupported-lock-environment")
        if "tool" in data:
            self.mapping(data["tool"])
        if "requires-python" in data:
            self.compatibility(data["requires-python"], "requires-python")
        packages = data.get("packages")
        if not isinstance(packages, list):
            raise InputRefusal("invalid-lock-packages")
        for index, entry in enumerate(packages):
            self.check()
            entry = self.mapping(entry)
            if any(
                key
                not in {
                    "name",
                    "version",
                    "marker",
                    "requires-python",
                    "dependencies",
                    "sdist",
                    "wheels",
                    "index",
                    "tool",
                    "vcs",
                    "directory",
                    "archive",
                }
                for key in entry
            ):
                raise InputRefusal("unsupported-lock-package-field")
            if any(key in entry for key in ("vcs", "directory", "archive")):
                raise InputRefusal("unsupported-lock-package-source")
            name = self.group(entry.get("name"))
            version = self.version(entry.get("version"))
            locator = f"packages[{index}]"
            marker = self.marker(entry["marker"]) if "marker" in entry else None
            compatibility = entry.get("requires-python")
            if compatibility is not None:
                self.compatibility(compatibility, locator + ".requires-python")
            if "index" in entry:
                self.url(entry["index"])
            if "tool" in entry:
                self.mapping(entry["tool"])
            wheels = entry.get("wheels", [])
            if not isinstance(wheels, list):
                raise InputRefusal("invalid-lock-list")
            hashes = set()
            for wheel in wheels:
                self.check()
                hashes.update(self.artifact(wheel, name, version, "wheel"))
            if "sdist" in entry:
                hashes.update(self.artifact(entry["sdist"], name, version, "sdist"))
            if not wheels and "sdist" not in entry:
                self.missing_source = True
            dependencies = entry.get("dependencies", [])
            if not isinstance(dependencies, list):
                raise InputRefusal("invalid-lock-list")
            selectors = []
            for dependency in dependencies:
                self.check()
                self.edges += 1
                self.retain()
                if self.edges > MAX_EDGES:
                    raise InputRefusal("lock-edge-budget-exceeded")
                dependency = self.mapping(dependency)
                if "name" not in dependency or any(key not in {"name", "version", "marker"} for key in dependency):
                    raise InputRefusal("unsupported-lock-dependency-selector")
                selector = {"name": self.group(dependency["name"])}
                if "version" in dependency:
                    selector["version"] = self.version(dependency["version"])
                if "marker" in dependency:
                    selector["marker"] = self.marker(dependency["marker"])
                selectors.append(tuple(selector.items()))
            self.add_package(
                LockedPackage(
                    name,
                    version,
                    locator,
                    marker=marker,
                    hashes=tuple(sorted(hashes)),
                    requires_python=compatibility,
                    dependencies=tuple(selectors),
                )
            )


def parse(path, content, fmt, *, deadline=None, max_records=MAX_RECORDS, check=None):
    path = relative_path(path)
    if fmt not in FORMATS:
        raise ValueError("unsupported-lock-parser")
    format_id, fmt = fmt, FORMATS[fmt]
    if not isinstance(content, bytes):
        raise TypeError("lock parser requires exact bytes")
    if len(content) > 2 * 1024 * 1024:
        raise InputRefusal("input-file-budget-exceeded")
    if type(max_records) is not int or not 0 <= max_records <= MAX_RECORDS:
        raise ValueError("invalid-parser-record-limit")
    parser_class = LockParser
    if fmt in {"poetry-lock", "uv-lock", "pdm-lock"}:
        from .python_lock_formats import PythonLockParser

        parser_class = PythonLockParser
    parser = parser_class(deadline if deadline is not None else time.monotonic() + 150, max_records)
    parser.shared_check = check
    sha256 = hashlib.sha256(content).hexdigest()

    def pairs(items):
        result = {}
        for key, value in items:
            parser.check()
            if key in result:
                raise InputRefusal("duplicate-lock-key")
            result[key] = value
        return result

    try:
        parser.check()
        text = content.decode("utf-8-sig")
        if fmt != "pipfile-lock" and tomllib is None:
            raise InputRefusal("unsupported-toml-runtime")
        if fmt == "pipfile-lock":
            data = json.loads(
                text,
                object_pairs_hook=pairs,
                parse_constant=lambda value: (_ for _ in ()).throw(InputRefusal("invalid-lock-number")),
            )
            parser.pipfile(data)
        elif fmt == "pylock":
            parser.pylock(tomllib.loads(text))
        else:
            getattr(parser, fmt.split("-", 1)[0])(tomllib.loads(text))
        parser.check()
        incomplete = parser.missing_source or parser.missing_metadata
        return Lock(
            path,
            format_id,
            sha256,
            "unsupported" if incomplete else "parsed",
            (
                "missing-lock-source"
                if parser.missing_source
                else ("missing-lock-metadata" if parser.missing_metadata else "static-input")
            ),
            tuple(parser.packages),
            tuple(parser.environment),
            record_count=parser.record_count,
        )
    except InputRefusal as refusal:
        reason = refusal.reason
    except UnicodeDecodeError:
        reason = "invalid-input-encoding"
    except (ValueError, RecursionError):
        reason = "invalid-lock-syntax"
    disposition = (
        "budget-exceeded"
        if "budget" in reason or "deadline" in reason
        else (
            "unsupported" if reason.startswith("unsupported-") or reason == "unselected-lock-version" else "malformed"
        )
    )
    return Lock(path, format_id, sha256, disposition, reason)
