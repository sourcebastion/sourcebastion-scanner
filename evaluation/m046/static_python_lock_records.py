"""Conditional registry lock graph evidence, distinct from installation state."""

from collections import defaultdict

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from .static_lock_records import identity
from .static_markers import disjoint
from .static_inputs import InputRefusal
from .static_manifests import MAX_RECORDS
from .static_poetry_constraints import constraint as poetry_constraint
from .static_poetry_constraints import version as poetry_version


def render(document, root, check):
    occurrences, relationships, environments = [], [], []
    by_name, variants = defaultdict(list), defaultdict(list)
    for package in document.packages:
        check()
        by_name[package.name].append(package)
        variants[(package.name, package.scope, package.extras)].append(package)
        record = {
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
            "activation": "unknown",
            "source_identity": package.source_key,
            "source_kind": "registry-asserted" if package.source_key else "unknown",
            "group": package.group,
        }
        if document.format == "poetry-lock":
            record["optional"] = package.optional
            record["requires_python_dialect"] = "poetry-core-2.1.3"
        occurrences.append(record)
    failure = None
    graph_failure = None
    for packages in variants.values():
        for index, left in enumerate(packages):
            for right in packages[index + 1 :]:
                check()
                # uv fork markers are not ordinary activation predicates. This
                # subset does not admit them, or infer disjointness from edges.
                if (
                    document.format == "uv-lock"
                    or not left.marker
                    or not right.marker
                    or not disjoint(left.marker, right.marker)
                ):
                    failure = ("unsupported", "overlapping-lock-variants")
    for parent in document.packages:
        resolved_contexts = {}
        for raw in parent.dependencies:
            check()
            selector = dict(raw)
            poetry = selector["dialect"] == "poetry-core-2.1.3"
            specifier = poetry_constraint(selector["specifier"]) if poetry else SpecifierSet(selector["specifier"])
            candidates = []
            if document.format == "uv-lock" and (selector["exact_version"] is None or selector["source"] is None):
                # Upstream fills *each* omitted identity component from the
                # global unambiguous-name table, never filtered candidates.
                named = by_name.get(selector["name"], ())
                if len(named) != 1:
                    graph_failure = ("unsupported", "ambiguous-lock-dependency" if named else "missing-lock-dependency")
                    continue
            for candidate in by_name.get(selector["name"], ()):
                check()
                if selector["source"] is not None and selector["source"] != candidate.source_key:
                    continue
                if document.format == "uv-lock" and selector["exact_version"] is not None:
                    accepted = Version(selector["exact_version"]) == Version(candidate.version)
                else:
                    accepted = (
                        specifier.allows(poetry_version(candidate.version))
                        if poetry
                        else specifier.contains(candidate.version, prereleases=True)
                    )
                if not accepted:
                    continue
                if document.format == "pdm-lock" and tuple(selector["extras"]) != candidate.extras:
                    continue
                candidates.append(candidate)
            # Repeated group occurrences belong to one physical lock entry.
            # Preserve the entry locator without guessing an installed group.
            physical = {candidate.entry: candidate for candidate in candidates}
            if len(physical) != 1:
                graph_failure = ("unsupported", "ambiguous-lock-dependency" if physical else "missing-lock-dependency")
                continue
            child = next(iter(physical.values()))
            if document.format == "uv-lock":
                key = (child.entry, tuple(sorted(selector["extras"])))
                if key in resolved_contexts:
                    graph_failure = (
                        ("malformed", "duplicate-lock-dependency")
                        if resolved_contexts[key] == selector["condition"]
                        else ("unsupported", "repeated-lock-dependency-context")
                    )
                    continue
                resolved_contexts[key] = selector["condition"]
            if len(relationships) >= MAX_RECORDS:
                raise InputRefusal("lock-edge-budget-exceeded")
            relationships.append(
                {
                    "parent": identity(parent),
                    "child": identity(child),
                    "path": document.path,
                    "locator": selector["locator"],
                    "root": root,
                    "kind": "dependency",
                    "parent_locator": parent.locator,
                    "child_locator": child.entry,
                    "child_source_identity": child.source_key,
                    "scope": parent.scope,
                    "group": parent.group,
                    "marker": selector["condition"],
                    "extras": list(selector["extras"]),
                    "declared_constraint": selector["declared_constraint"],
                    "constraint_dialect": "exact-identity" if document.format == "uv-lock" else selector["dialect"],
                    "marker_semantics": (
                        "simplified-relative-to-root-python" if document.format == "uv-lock" else "pep508"
                    ),
                    "activation": "unknown",
                }
            )
            if document.format == "uv-lock":
                relationships[-1]["exact_version"] = selector["exact_version"]
    parents = {package.entry: package for package in document.packages}
    for locator, compatibility in document.environment:
        check()
        parent = parents.get(locator.rsplit(".", 1)[0])
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
        if document.format == "poetry-lock":
            record["constraint_dialect"] = "poetry-core-2.1.3"
        environments.append(record)
    return {
        "occurrences": occurrences,
        "relationships": relationships if not graph_failure else [],
        "environment": environments,
        "status": graph_failure or failure or (document.disposition, document.reason),
        "graph": "evidenced-only" if relationships and not graph_failure else "unknown",
    }
