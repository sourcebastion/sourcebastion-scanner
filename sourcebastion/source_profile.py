"""Source profile: aggregate counts from a repository's path list (M066 S01).

Input is a path list only, as ``git ls-tree -r -z --name-only HEAD`` prints it:
NUL-delimited, untrusted bytes. No file is opened and no content is read. The
output is aggregates over a fixed vocabulary from the versioned lookup table
(``data/source_profile_table.json``), so no path, file name or directory name
from the input can appear in it.

Extension and name matches are hints. A YAML path does not prove Kubernetes or
CloudFormation content, so it is counted as ``yaml-candidate`` and never
narrows scanner coverage.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import posixpath
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from sourcebastion.inventory.registry import FORMAT_ECOSYSTEMS, NAMES as MANIFEST_NAMES

PROFILE_VERSION = "sourcebastion.source-profile/1"
TABLE_PATH = Path(__file__).with_name("data") / "source_profile_table.json"

# Bounds before any work: an oversized input stops with a fixed status rather
# than being partly counted. linux has about 97,000 paths, so 1,000,000 leaves
# room for real monorepos while bounding memory.
MAX_PATHS = 1_000_000
MAX_PATH_BYTES = 4096
MAX_INPUT_BYTES = 256 * 1024 * 1024

PATH_CLASSES = ("production", "vendored", "generated", "test", "docs")


class ProfileInputError(ValueError):
    """A fixed status code; never carries input text."""

    def __init__(self, status: str):
        super().__init__(status)
        self.status = status


@dataclass(frozen=True)
class Table:
    version: str
    sha256: str
    language_extensions: dict
    infra_names: dict
    infra_name_prefixes: dict
    infra_extensions: dict
    manifest_patterns: dict
    class_order: tuple
    classes: dict

    @property
    def languages(self) -> frozenset:
        return frozenset(self.language_extensions.values())

    @property
    def infrastructure(self) -> frozenset:
        return frozenset(
            [*self.infra_names.values(), *self.infra_name_prefixes.values(), *self.infra_extensions.values()]
        )

    @property
    def manifest_types(self) -> frozenset:
        return frozenset([*MANIFEST_NAMES.values(), *self.manifest_patterns.values()])


@lru_cache(maxsize=1)
def load_table(path: Path = TABLE_PATH) -> Table:
    raw = path.read_bytes()
    data = json.loads(raw)
    classes = data["path_classes"]
    order = tuple(classes["order"])
    if set(order) != set(PATH_CLASSES) - {"production"}:
        raise RuntimeError("source-profile-table-classes-incomplete")
    return Table(
        version=data["version"],
        # The manifest names come from the inventory registry, so they are part
        # of the table's identity too: a registry change re-versions profiles.
        sha256=hashlib.sha256(raw + json.dumps(MANIFEST_NAMES, sort_keys=True).encode()).hexdigest(),
        language_extensions=dict(data["languages"]["extensions"]),
        infra_names=dict(data["infrastructure"]["names"]),
        infra_name_prefixes=dict(data["infrastructure"]["name_prefixes"]),
        infra_extensions=dict(data["infrastructure"]["extensions"]),
        manifest_patterns=dict(data["manifests"]["patterns"]),
        class_order=order,
        classes={name: classes[name] for name in order},
    )


def _extension(name: str) -> str:
    return posixpath.splitext(name)[1].lower()


def path_class(path: str, table: Table) -> str:
    """The first matching class in table order, else ``production``."""
    parts = path.split("/")
    directories, name = parts[:-1], parts[-1]
    lowered = {part.lower() for part in directories}
    for cls in table.class_order:
        rules = table.classes[cls]
        if lowered & {d.lower() for d in rules.get("directories", ())}:
            return cls
        if any(name.endswith(s) for s in rules.get("name_suffixes", ())):
            return cls
        if any(name.startswith(p) for p in rules.get("name_prefixes", ())):
            return cls
        if any(i in name for i in rules.get("name_infixes", ())):
            return cls
        if _extension(name) in rules.get("extensions", ()):
            return cls
    return "production"


def language(name: str, table: Table) -> str | None:
    return table.language_extensions.get(_extension(name))


def infrastructure(name: str, table: Table) -> str | None:
    if name in table.infra_names:
        return table.infra_names[name]
    for prefix, kind in table.infra_name_prefixes.items():
        if name.startswith(prefix):
            return kind
    return table.infra_extensions.get(_extension(name))


def manifest_type(name: str, table: Table) -> str | None:
    if name in MANIFEST_NAMES:
        return MANIFEST_NAMES[name]
    for pattern, kind in table.manifest_patterns.items():
        if fnmatch.fnmatchcase(name, pattern):
            return kind
    return None


def split_paths(data: bytes) -> list[str]:
    """NUL-delimited untrusted bytes -> bounded relative paths."""
    if len(data) > MAX_INPUT_BYTES:
        raise ProfileInputError("too_large")
    paths = []
    for item in data.split(b"\0"):
        if not item:
            continue
        if len(item) > MAX_PATH_BYTES:
            raise ProfileInputError("invalid_path")
        if len(paths) >= MAX_PATHS:
            raise ProfileInputError("too_large")
        # Classification only reads ASCII suffixes and directory names, so a
        # replaced undecodable byte cannot change a match.
        text = item.decode("utf-8", errors="replace")
        if text.startswith("/") or "\n" in text:
            raise ProfileInputError("invalid_path")
        paths.append(text)
    return paths


def profile(paths: list[str], table: Table | None = None) -> dict:
    """Aggregate counts. Every key is from the table's fixed vocabulary."""
    table = table or load_table()
    languages: Counter = Counter()
    infra: Counter = Counter()
    classes: Counter = Counter()
    manifests: set = set()
    for path in paths:
        name = path.rsplit("/", 1)[-1]
        classes[path_class(path, table)] += 1
        if (lang := language(name, table)) is not None:
            languages[lang] += 1
        if (kind := infrastructure(name, table)) is not None:
            infra[kind] += 1
        if (manifest := manifest_type(name, table)) is not None:
            manifests.add(manifest)
    return {
        "version": PROFILE_VERSION,
        "table_version": table.version,
        "table_sha256": table.sha256,
        "status": "ok",
        "path_count": len(paths),
        "languages": dict(sorted(languages.items())),
        "infrastructure": dict(sorted(infra.items())),
        "path_classes": {cls: classes.get(cls, 0) for cls in PATH_CLASSES},
        "manifest_types": sorted(manifests),
        "ecosystems": sorted({FORMAT_ECOSYSTEMS[m] for m in manifests if m in FORMAT_ECOSYSTEMS}),
    }


def profile_bytes(data: bytes, table: Table | None = None) -> dict:
    """Profile a NUL-delimited path list, or return a fixed refusal status."""
    table = table or load_table()
    try:
        paths = split_paths(data)
    except ProfileInputError as exc:
        return {
            "version": PROFILE_VERSION,
            "table_version": table.version,
            "table_sha256": table.sha256,
            "status": exc.status,
        }
    return profile(paths, table)
