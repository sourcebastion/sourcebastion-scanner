"""Render typed declarations without installing or guessing lock selections."""

from collections import defaultdict

from packaging.specifiers import SpecifierSet

from .static_inputs import InputRefusal
from .static_markers import context_key, disjoint


def render(document, root, check):
    groups = defaultdict(list)
    rows = []
    for declaration in document.declarations:
        check()
        record = declaration.requirement
        key = (record.name, declaration.scope, context_key(record.marker))
        groups[key].append(declaration)
        rows.append((declaration, key))
    failure = None
    by_name_scope = defaultdict(list)
    signatures = {}
    for key, declarations in groups.items():
        check()
        by_name_scope[key[:2]].append((key, declarations))
        signature = set()
        for declaration in declarations:
            check()
            signature.add(declaration.requirement.specifier)
        signatures[key] = signature
    for contexts in by_name_scope.values():
        for index, (left_key, left) in enumerate(contexts):
            for right_key, right in contexts[index + 1 :]:
                check()
                a, b = left[0].requirement, right[0].requirement
                if a.marker is None or b.marker is None:
                    continue
                if signatures[left_key] != signatures[right_key] and not disjoint(a.marker, b.marker):
                    failure = ("unsupported", "overlapping-marker-context-unresolved")
    occurrences, unresolved = [], []
    selections = {}
    for key, members in groups.items():
        check()
        siblings = [*members]
        if members[0].requirement.marker is not None:
            siblings.extend(groups.get((key[0], key[1], context_key(None)), ()))
        known, specifications = set(), set()
        for sibling in siblings:
            check()
            if sibling.requirement.exact_version is not None:
                known.add(sibling.requirement.exact_version)
            specifications.add(sibling.requirement.specifier)
        contracts = [SpecifierSet(specification) for specification in sorted(specifications)]
        compatible = []
        for candidate in sorted(known):
            matches = True
            for contract in contracts:
                check()
                try:
                    accepted = contract.contains(candidate, prereleases=True)
                except (ValueError, RecursionError):
                    raise InputRefusal("invalid-version-selection") from None
                if not accepted:
                    matches = False
                    break
            if matches:
                compatible.append(candidate)
        if known and not compatible:
            failure = ("malformed", "conflicting-root-declarations")
        selections[key] = compatible
    for declaration, key in rows:
        check()
        record = declaration.requirement
        scope = declaration.scope
        compatible = selections[key]
        selected = (
            record.exact_version if record.exact_version in compatible else (compatible[0] if compatible else None)
        )
        if selected is None:
            unresolved.append(
                {
                    "name": "pypi:" + record.name,
                    "range": record.specifier,
                    "path": document.path,
                    "locator": declaration.locator,
                    "root": root,
                    "scope": scope,
                    "marker": record.marker,
                    "extras": list(record.extras),
                    "classification": "direct-declared",
                }
            )
        else:
            occurrences.append(
                {
                    "package": f"pypi:{record.name}@{selected}",
                    "path": document.path,
                    "locator": declaration.locator,
                    "root": root,
                    "selection": "declared-pin" if selected == record.exact_version else "constrained",
                    "scope": scope,
                    "marker": record.marker,
                    "extras": list(record.extras),
                    "declared_range": record.specifier,
                    "hashes": [],
                    "relationship": "direct",
                    "requires_python": None,
                    "activation": (
                        "unknown"
                        if record.marker or scope.startswith("optional:") or document.environment
                        else "unconditional"
                    ),
                }
            )
    if failure:
        return {
            "occurrences": [],
            "declarations": [],
            "applications": [],
            "environment": [],
            "status": failure,
            "unresolved": True,
        }
    environments = [
        {
            "root": root,
            "path": document.path,
            "locator": locator,
            "requires_python": value,
            "activation": "unknown",
            "kind": "root",
        }
        for locator, value in document.environment
    ]
    applications = (
        [{"root": root, "path": document.path, "identity": document.application}] if document.application else []
    )
    status = (
        ("declaration-only", "no-selected-version") if unresolved and not occurrences else ("parsed", "static-input")
    )
    return {
        "occurrences": occurrences,
        "declarations": unresolved,
        "applications": applications,
        "environment": environments,
        "status": status,
        "unresolved": bool(unresolved),
    }
