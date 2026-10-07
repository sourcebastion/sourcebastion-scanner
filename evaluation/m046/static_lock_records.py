"""Root-aware locked occurrences and unambiguous informational lock edges."""

from collections import defaultdict
from .static_markers import disjoint


def identity(package):
    return f"pypi:{package.name}@{package.version}"


def render(document, root, check):
    occurrences, relationships, environments = [], [], []
    by_name = defaultdict(list)
    for package in document.packages:
        check()
        by_name[package.name].append(package)
    root_environment = any(not locator.startswith("packages[") for locator, _value in document.environment)
    overlaps = set()
    by_name_scope = defaultdict(list)
    for package in document.packages:
        by_name_scope[(package.name, package.scope)].append(package)
    for key, packages in by_name_scope.items():
        for index, left in enumerate(packages):
            for right in packages[index + 1 :]:
                check()
                if left.marker is None or right.marker is None or not disjoint(left.marker, right.marker):
                    overlaps.add(key)
    for package in document.packages:
        check()
        occurrences.append(
            {
                "package": identity(package),
                "path": document.path,
                "locator": package.locator,
                "root": root,
                "selection": "locked",
                "scope": package.scope,
                "marker": package.marker,
                "extras": list(package.extras),
                "declared_range": package.declared_range,
                "hashes": list(package.hashes),
                "relationship": "unknown",
                "requires_python": package.requires_python,
                "activation": (
                    "unknown"
                    if package.marker
                    or package.requires_python
                    or root_environment
                    or (package.name, package.scope) in overlaps
                    or document.reason == "missing-lock-metadata"
                    or package.scope.startswith("group:")
                    else "unconditional"
                ),
            }
        )
    failure = ("unsupported", "overlapping-lock-variants") if overlaps else None
    for package in document.packages:
        for index, fields in enumerate(package.dependencies):
            check()
            selector = dict(fields)
            candidates = []
            for candidate in by_name.get(selector["name"], ()):
                check()
                if "version" in selector and selector["version"] != candidate.version:
                    continue
                if "marker" in selector and selector["marker"] != candidate.marker:
                    continue
                candidates.append(candidate)
            if len(candidates) != 1:
                failure = ("unsupported", "ambiguous-lock-dependency" if candidates else "missing-lock-dependency")
                continue
            relationships.append(
                {
                    "parent": identity(package),
                    "child": identity(candidates[0]),
                    "path": document.path,
                    "locator": package.locator + f".dependencies[{index}]",
                    "root": root,
                    "kind": "dependency",
                }
            )
    by_locator = {package.locator: package for package in document.packages}
    for locator, compatibility in document.environment:
        check()
        parent = by_locator.get(locator.rsplit(".", 1)[0])
        record = {
            "root": root,
            "path": document.path,
            "locator": locator,
            "requires_python": compatibility,
            "activation": "unknown",
            "kind": "package" if parent else "root",
        }
        if parent:
            record["package"] = identity(parent)
        environments.append(record)
    return {
        "occurrences": occurrences,
        "relationships": relationships if not failure else [],
        "environment": environments,
        "status": failure or (document.disposition, document.reason),
        "graph": "evidenced-only" if relationships and not failure else "unknown",
    }
