"""Maintained format dispatch; customer mappings are bounded data only."""

from dataclasses import dataclass
import hashlib
import json
import posixpath
import re

from .inputs import relative_path

VERSION = "sourcebastion.inventory-registry/1"
# Names select built-in parsers, never executables or imports. Formats without
# a reviewed canonical adapter remain explicit unsupported source evidence.
NAMES = {
    "pyproject.toml": "python-pyproject",
    "setup.cfg": "python-setup-cfg",
    "setup.py": "python-setup-static",
    "Pipfile": "python-pipfile",
    "Pipfile.lock": "python-pipfile-lock",
    "poetry.lock": "python-poetry-lock",
    "uv.lock": "python-uv-lock",
    "pdm.lock": "python-pdm-lock",
    "package.json": "npm-manifest",
    "package-lock.json": "npm-lock",
    "npm-shrinkwrap.json": "npm-lock",
    "pnpm-lock.yaml": "pnpm-lock",
    "yarn.lock": "yarn-lock",
    "go.mod": "go-mod",
    "go.sum": "go-sum",
    "Cargo.toml": "cargo-manifest",
    "Cargo.lock": "cargo-lock",
    "pom.xml": "maven-pom",
    "build.gradle": "gradle-manifest",
    "build.gradle.kts": "gradle-manifest",
    "gradle.lockfile": "gradle-lock",
    "buildscript-gradle.lockfile": "gradle-lock",
    "packages.lock.json": "nuget-lock",
    "packages.config": "nuget-packages",
    "Gemfile": "bundler-manifest",
    "Gemfile.lock": "bundler-lock",
    "composer.json": "composer-manifest",
    "composer.lock": "composer-lock",
}
FORMATS = frozenset(NAMES.values()) | {
    "pip-requirements",
    "python-pylock",
    "python-uv-script-lock",
    "python-installed-metadata",
}
REGISTRY_SHA256 = hashlib.sha256(
    json.dumps(
        {
            "version": VERSION,
            "names": NAMES,
            "formats": sorted(FORMATS),
            "rules": [
                "pylock[.name].toml",
                "*.py.lock",
                "dist-info/METADATA",
                "egg-info/PKG-INFO",
                "*.egg-info",
                "*.in",
                "*.txt",
                "*.pip",
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
).hexdigest()


@dataclass(frozen=True)
class DiscoveryConfig:
    mappings: tuple = ()
    ignored: tuple = ()
    include_depth: int = 64
    include_targets: int = 4096
    semantic_checks: int = 5000000

    def __post_init__(self):
        if not isinstance(self.mappings, tuple) or len(self.mappings) > 4096:
            raise ValueError("invalid-format-mappings")
        seen = set()
        for item in self.mappings:
            if not isinstance(item, tuple) or len(item) != 2:
                raise ValueError("invalid-format-mappings")
            path, fmt = item
            if relative_path(path) != path or fmt not in FORMATS or path in seen:
                raise ValueError("invalid-format-mappings")
            seen.add(path)
        if not isinstance(self.ignored, tuple) or len(self.ignored) > 4096:
            raise ValueError("invalid-ignore-paths")
        for path in self.ignored:
            if relative_path(path) != path:
                raise ValueError("invalid-ignore-paths")
        for value, maximum in ((self.include_depth, 64), (self.include_targets, 4096), (self.semantic_checks, 5000000)):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise ValueError("invalid-discovery-limits")

    def ignores(self, path):
        return any(part in {".git", ".hg", ".svn"} for part in path.split("/")) or any(
            path == prefix or path.startswith(prefix + "/") for prefix in self.ignored
        )

    @property
    def sha256(self):
        data = {
            "mappings": sorted(self.mappings),
            "ignored": sorted(set(self.ignored)),
            "include_depth": self.include_depth,
            "include_targets": self.include_targets,
            "semantic_checks": self.semantic_checks,
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def format_for(path, config):
    mapped = dict(config.mappings).get(path)
    if mapped:
        return mapped
    name = posixpath.basename(path)
    if name in NAMES:
        return NAMES[name]
    if re.fullmatch(r"pylock(?:\.[^.]+)?\.toml", name):
        return "python-pylock"
    if name.endswith(".py.lock"):
        return "python-uv-script-lock"
    parent = posixpath.basename(posixpath.dirname(path)).lower()
    if (
        (name == "METADATA" and parent.endswith(".dist-info"))
        or (name == "PKG-INFO" and parent.endswith(".egg-info"))
        or name.lower().endswith(".egg-info")
    ):
        return "python-installed-metadata"
    if posixpath.splitext(name)[1] in {".in", ".txt", ".pip"}:
        return "pip-requirements"
    return None
