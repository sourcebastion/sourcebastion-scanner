"""Controlled static pip registry/root/constraint experiment for M046 S01.

This is engine-neutral evaluation code. Other formats are explicitly unsupported
until their typed adapters exist. It is not wired into the production scanner.
"""

from collections import defaultdict
from dataclasses import asdict
import posixpath
import re

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from .static_inputs import InputRefusal, Source, relative_path
from .static_markers import context_key, disjoint
from .static_requirements import Document, parse

VERSION = "m046-static-inventory-prototype-v1"
MAX_OCCURRENCES = 100000
MAX_INCLUDE_DEPTH = 64
MAX_INCLUDE_TARGETS = 4096
MAX_RESOLUTION_STEPS = 5000000
OTHER_FORMATS = {
    "pyproject.toml": "pep621",
    "setup.cfg": "setup-cfg",
    "setup.py": "setup-python-static",
    "Pipfile.lock": "pipfile-lock",
    "poetry.lock": "poetry-lock",
    "uv.lock": "uv-lock",
    "pdm.lock": "pdm-lock",
    "package.json": "npm-manifest",
    "package-lock.json": "npm-lock-v3",
    "pnpm-lock.yaml": "pnpm-lock-v9",
    "yarn.lock": "yarn-lock-v1",
    "go.mod": "go-mod",
    "go.sum": "go-sum",
    "Cargo.toml": "cargo-manifest",
    "Cargo.lock": "cargo-lock-v3",
    "gradle.lockfile": "gradle-lock",
    "packages.lock.json": "nuget-lock",
    "Gemfile.lock": "bundler-lock",
    "composer.lock": "composer-lock",
}


def format_for(path, mapping):
    if path in mapping:
        return mapping[path]
    name = posixpath.basename(path)
    if name in OTHER_FORMATS:
        return OTHER_FORMATS[name]
    if re.fullmatch(r"pylock(?:\.[^.]+)?\.toml", name):
        return "pylock"
    if posixpath.splitext(name)[1] in {".in", ".txt", ".pip"}:
        return "pip-requirements"
    return "unrecognized"


def mapping_config(mapping):
    if mapping is None:
        return {}
    if not isinstance(mapping, dict) or len(mapping) > 4096:
        raise ValueError("invalid-format-mapping")
    result = {}
    for path, fmt in mapping.items():
        path = relative_path(path)
        if fmt != "pip-requirements" or path in result:
            raise ValueError("invalid-format-mapping")
        result[path] = fmt
    return result


def is_constraint(path):
    return bool(re.fullmatch(r"constraints(?:[-_.].*)?\.(?:txt|in|pip)", posixpath.basename(path)))


def evaluate(source, *, mapping=None):
    mapping = mapping_config(mapping)
    try:
        return _evaluate(source, mapping=mapping)
    except InputRefusal as refusal:
        # A failed source epoch/deadline cannot authorize a partial package
        # selection. Preserve the stable refusal and explicit unknown axes.
        return {
            "schema_version": VERSION,
            "inventory_status": "failed",
            "sbom_status": "not-run",
            "matching_status": "not-run",
            "packages": [],
            "edges": [],
            "application_identities": [],
            "coverage": "prototype-pip-only",
            "refusal_codes": [refusal.reason],
            "semantic_dimensions": {
                "inputs": [],
                "occurrences": [],
                "relationships": [],
                "declaration_records": [],
                "references": [],
                "roots": [],
                "applications": [],
                "environment_records": [],
                "fidelity": {
                    "discovery": "partial",
                    "parsing": "partial",
                    "enumeration": "partial",
                    "version_selection": "partial",
                    "graph": "unknown",
                    "environment": "unknown",
                },
            },
        }


def _evaluate(source, *, mapping=None):
    if not isinstance(source, Source):
        raise TypeError("controller-bound Source required")
    mapping = mapping_config(mapping)
    source.check()
    inputs, documents, refs = {}, {}, []
    roots_for = defaultdict(set)
    outcomes = defaultdict(list)
    refusal_codes = []
    discovery = "complete"
    parsed_records = 0
    resolution_steps = 0

    def step():
        nonlocal resolution_steps
        source.check()
        resolution_steps += 1
        if resolution_steps > MAX_RESOLUTION_STEPS:
            raise InputRefusal("resolution-step-budget-exceeded")

    def append(records, value):
        step()
        if len(records) >= MAX_OCCURRENCES:
            raise InputRefusal("semantic-expansion-budget-exceeded")
        records.append(value)

    def extend(records, values):
        for value in values:
            append(records, value)

    def load(path, *, forced=False):
        nonlocal parsed_records
        if path in documents:
            return documents[path]
        fmt = "pip-requirements" if forced else format_for(path, mapping)
        base = {"path": path, "format": fmt, "sha256": None, "roots": []}
        try:
            data = source.read(path)
            base["sha256"] = data.sha256
            document = parse(
                path,
                data.content,
                explicit=forced or path in mapping or is_constraint(path),
                deadline=source.deadline,
                max_records=MAX_OCCURRENCES - parsed_records,
            )
            parsed_records += len(document.requirements) + len(document.references)
            documents[path] = document
            inputs[path] = {**base, "disposition": document.disposition, "reason": document.reason}
            if document.disposition == "ignored":
                inputs[path]["format"] = "unrecognized"
            return document
        except InputRefusal as refusal:
            refusal_codes.append(refusal.reason)
            disposition = "budget-exceeded" if "budget" in refusal.reason or "deadline" in refusal.reason else "unsafe"
            inputs[path] = {**base, "disposition": disposition, "reason": refusal.reason}
            document = Document(path, base["sha256"], (), (), disposition, refusal.reason)
            documents[path] = document
            return document

    try:
        for entry in source.discover():
            if entry.kind == "directory":
                continue
            fmt = format_for(entry.path, mapping)
            base = {"path": entry.path, "format": fmt, "sha256": None, "roots": []}
            if entry.kind != "file":
                inputs[entry.path] = {
                    **base,
                    "format": entry.kind,
                    "disposition": "unsafe",
                    "reason": "non-regular-input",
                }
            elif fmt == "pip-requirements":
                load(entry.path)
            elif fmt == "unrecognized":
                inputs[entry.path] = {**base, "disposition": "ignored", "reason": "unrecognized-input"}
            else:
                # Unknown-to-this-adapter formats are never reported as parsed.
                inputs[entry.path] = {**base, "disposition": "unsupported", "reason": "parser-not-implemented"}
    except InputRefusal as refusal:
        discovery = "partial"
        refusal_codes.append(refusal.reason)

    for path in sorted(mapping):
        if path not in inputs:
            load(path, forced=True)
            discovery = "partial"
            refusal_codes.append("mapped-input-not-discovered")

    # Includes may refer to a nonstandard extension. Parse only their literal,
    # controller-confined paths. Every exact byte snapshot counts once.
    pending = list(sorted(documents))
    index = 0
    while index < len(pending):
        source.check()
        path = pending[index]
        index += 1
        document = documents[path]
        if document.disposition != "parsed":
            continue
        for reference in document.references:
            if reference.reason or reference.target is None:
                continue
            if reference.target not in documents:
                load(reference.target, forced=True)
                pending.append(reference.target)
                if len(pending) > source.limits.entries:
                    refusal_codes.append("input-count-budget-exceeded")
                    discovery = "partial"
                    break
        if len(pending) > source.limits.entries:
            break

    incoming = {
        reference.target
        for document in documents.values()
        for reference in document.references
        if reference.target is not None and reference.reason is None
    }
    candidates = {path for path, document in documents.items() if document.disposition == "parsed"}
    seeds = sorted((candidates | {path for path, document in documents.items() if document.references}) - incoming)
    seen_scopes = set()
    claimed_scopes = set()
    occurrences, declarations, all_roots = [], [], set()
    unresolved = False

    def context(seed):
        nonlocal unresolved
        root = posixpath.dirname(seed) or "."
        all_roots.add(root)
        # Planning records ownership even when a resolution budget stops DFS.
        # An unvisited include target must never become an independent root.
        planned, pending_paths = set(), [seed]
        while pending_paths:
            step()
            planned_path = pending_paths.pop()
            if planned_path in planned:
                continue
            planned.add(planned_path)
            roots_for[planned_path].add(root)
            planned_document = documents.get(planned_path)
            if planned_document:
                pending_paths.extend(
                    reference.target
                    for reference in planned_document.references
                    if reference.target is not None and reference.reason is None
                )
        claimed_scopes.update(planned)
        visited, targets, stack, required, constraints = set(), set(), [], [], []
        context_refs, failure = [], None

        def visit(path, role, depth):
            nonlocal failure
            source.check()
            roots_for[path].add(root)
            seen_scopes.add(path)
            if path in stack:
                failure = failure or ("malformed", "include-cycle")
                for cyclic in stack[stack.index(path) :]:
                    outcomes[cyclic].append(("malformed", "include-cycle"))
                return
            if depth > MAX_INCLUDE_DEPTH:
                failure = failure or ("budget-exceeded", "include-depth-budget-exceeded")
                return
            key = (path, role)
            if key in visited:
                return
            visited.add(key)
            document = documents.get(path)
            if document is None or document.disposition != "parsed":
                status, reason = (document.disposition, document.reason) if document else ("unsafe", "missing-include")
                failure = failure or (status, reason)
                return
            stack.append(path)
            extend(
                constraints if role == "constraint" else required, ((path, record) for record in document.requirements)
            )
            for reference in document.references:
                reference_record = {
                    "kind": reference.kind + ("-refused" if reference.reason else ""),
                    "path": path,
                    "target": reference.target,
                    "locator": f"line:{reference.line}",
                    "root": root,
                }
                if reference.reason:
                    reference_record["reason"] = reference.reason
                append(context_refs, reference_record)
                if reference.reason or reference.target is None:
                    failure = failure or ("unsafe", reference.reason or "invalid-reference")
                    continue
                targets.add(reference.target)
                if len(targets) > MAX_INCLUDE_TARGETS:
                    failure = failure or ("budget-exceeded", "include-target-budget-exceeded")
                    break
                child_role = "constraint" if role == "constraint" or reference.kind == "constraint" else "required"
                visit(reference.target, child_role, depth + 1)
            stack.pop()

        visit(seed, "constraint" if is_constraint(seed) else "required", 0)
        extend(refs, context_refs)
        constraints_for = defaultdict(list)
        required_for = defaultdict(list)
        marker_contexts = defaultdict(dict)
        for path, record in required:
            key = context_key(record.marker)
            append(required_for[(record.name, key)], (path, record))
            marker_contexts[record.name].setdefault(key, record)
        for name, contexts in marker_contexts.items():
            representatives = list(contexts.items())
            signatures = {}
            for key, _record in representatives:
                signatures[key] = frozenset(record.specifier for _path, record in required_for[(name, key)])
            for index, (left_key, left) in enumerate(representatives):
                for right_key, right in representatives[index + 1 :]:
                    step()
                    if left.marker is None or right.marker is None:
                        continue
                    if signatures[left_key] != signatures[right_key] and not disjoint(left.marker, right.marker):
                        failure = failure or ("unsupported", "overlapping-marker-context-unresolved")
        for path, record in constraints:
            source.check()
            constraints_for[record.name].append((path, record))
            if record.extras:
                failure = failure or ("malformed", "invalid-constraint-extras")
            append(
                declarations,
                {
                    "name": "pypi:" + record.name,
                    "range": record.specifier,
                    "path": path,
                    "locator": f"line:{record.line}",
                    "root": root,
                    "scope": "constraint",
                    "marker": record.marker,
                    "extras": list(record.extras),
                    "classification": "unknown",
                },
            )
            outcomes[path].append(("declaration-only", "constraint-only"))
        prepared = []
        exacts_for = defaultdict(set)
        for path, record in required:
            source.check()
            applicable = []
            for constraint_path, constraint in constraints_for[record.name]:
                step()
                if constraint.marker is not None and context_key(constraint.marker) != context_key(record.marker):
                    failure = failure or ("unsupported", "conditional-constraint-unresolved")
                else:
                    append(applicable, (constraint_path, constraint))
            siblings = list(required_for[(record.name, context_key(record.marker))])
            if record.marker is not None:
                siblings += required_for[(record.name, context_key(None))]
            evidence = [*siblings, *applicable]
            selections, selectors = set(), []
            for _evidence_path, declaration in evidence:
                step()
                if declaration.exact_version is not None:
                    selections.add(declaration.exact_version)
                selectors.append(SpecifierSet(declaration.specifier))
            compatible = []
            for candidate in sorted(selections):
                matches = True
                for selector in selectors:
                    step()
                    try:
                        accepted = selector.contains(candidate, prereleases=True)
                    except (ValueError, RecursionError):
                        raise InputRefusal("invalid-version-selection") from None
                    if not accepted:
                        matches = False
                        break
                if matches:
                    compatible.append(candidate)
            if selections and not compatible:
                reason = "constraint-conflict" if applicable else "conflicting-root-declarations"
                failure = failure or ("malformed", reason)
            selected = (
                record.exact_version if record.exact_version in compatible else (compatible[0] if compatible else None)
            )
            if selected:
                exacts_for[(record.name, context_key(record.marker))].add(Version(selected))
            append(prepared, (path, record, selected, evidence))
        if any(len(values) > 1 for values in exacts_for.values()):
            failure = failure or ("malformed", "conflicting-root-declarations")
        new_occurrences, new_refs = [], []
        for path, record, selected, applicable in prepared:
            source.check()
            constrained = selected is not None and selected != record.exact_version
            if selected is None or constraints_for[record.name] or constrained or failure:
                append(
                    declarations,
                    {
                        "name": "pypi:" + record.name,
                        "range": record.specifier,
                        "path": path,
                        "locator": f"line:{record.line}",
                        "root": root,
                        "scope": "unknown",
                        "marker": record.marker,
                        "extras": list(record.extras),
                        "classification": "unknown",
                    },
                )
            if selected is None:
                unresolved = True
                outcomes[path].append(("declaration-only", "no-selected-version"))
                continue
            if failure:
                continue
            append(
                new_occurrences,
                {
                    "package": f"pypi:{record.name}@{selected}",
                    "path": path,
                    "locator": f"line:{record.line}",
                    "root": root,
                    "selection": "constrained" if constrained else "declared-pin",
                    "scope": "unknown",
                    "marker": record.marker,
                    "extras": list(record.extras),
                    "declared_range": record.specifier,
                    "hashes": list(record.hashes),
                    "relationship": "unknown",
                    "requires_python": None,
                    "activation": "unknown" if record.marker else "unconditional",
                },
            )
            if constrained:
                for constraint_path, constraint in applicable:
                    if constraint.exact_version == selected:
                        append(
                            new_refs,
                            {
                                "kind": "version-evidence",
                                "path": path,
                                "target": constraint_path,
                                "locator": f"line:{record.line}",
                                "root": root,
                            },
                        )
        if failure:
            refusal_codes.append(failure[1])
            outcomes[seed].append(failure)
            for path, role in visited:
                if role != "constraint":
                    outcomes[path].append(failure)
            if failure[0] == "budget-exceeded":
                for path in planned - {path for path, _role in visited}:
                    outcomes[path].append(failure)
        elif len(new_occurrences) + len(occurrences) > MAX_OCCURRENCES:
            refusal_codes.append("occurrence-budget-exceeded")
            for path, _ in visited:
                outcomes[path].append(("budget-exceeded", "occurrence-budget-exceeded"))
        else:
            extend(occurrences, new_occurrences)
            extend(refs, new_refs)
            if not required:
                outcomes[seed].append(("declaration-only", "no-required-package"))
            elif documents[seed].references:
                outcomes[seed].append(("parsed", "static-input"))
            for path, _record, selected, _applicable in prepared:
                if selected is not None:
                    outcomes[path].append(("parsed", "static-input"))

    for seed in seeds:
        context(seed)
    # A wholly cyclic component has no zero-incoming seed. Select a deterministic
    # source and let bounded DFS expose the cycle instead of dropping the input.
    for seed in sorted(candidates - claimed_scopes):
        if seed not in claimed_scopes:
            context(seed)
    for path, document in sorted(documents.items()):
        if document.disposition == "parsed":
            continue
        for root in sorted(roots_for[path] or {posixpath.dirname(path) or "."}):
            for reference in document.references:
                append(
                    refs,
                    {
                        "kind": reference.kind + ("-refused" if reference.reason else ""),
                        "path": path,
                        "target": reference.target,
                        "locator": f"line:{reference.line}",
                        "root": root,
                    },
                )
    rank = {
        "ignored": 0,
        "parsed": 1,
        "declaration-only": 2,
        "unsupported": 3,
        "malformed": 4,
        "unsafe": 5,
        "budget-exceeded": 6,
    }
    for path, record in inputs.items():
        source.check()
        roots = sorted(roots_for[path] or {posixpath.dirname(path) or "."})
        record["roots"] = roots
        all_roots.update(roots)
        if outcomes[path]:
            # Selected and unresolved requirements in one file remain partial
            # version selection; the file is still successfully parsed.
            options = outcomes[path]
            if any(status == "parsed" for status, _reason in options) and all(
                rank[status] <= 2 for status, _reason in options
            ):
                record.update(disposition="parsed", reason="static-input")
            else:
                status, reason = max(options, key=lambda pair: rank[pair[0]])
                record.update(disposition=status, reason=reason)
        elif record["disposition"] == "parsed" and not documents[path].requirements:
            record.update(disposition="declaration-only", reason="no-required-package")
    partial = discovery != "complete" or any(
        record["disposition"] in {"unsupported", "malformed", "unsafe", "budget-exceeded"} for record in inputs.values()
    )
    dimensions = {
        "inputs": [inputs[path] for path in sorted(inputs)],
        "occurrences": occurrences,
        "relationships": [],
        "declaration_records": declarations,
        "references": refs,
        "roots": sorted(all_roots),
        "applications": [],
        "environment_records": [],
        "fidelity": {
            "discovery": discovery,
            "parsing": "partial" if partial else "complete",
            "enumeration": "partial" if partial else "complete",
            "version_selection": "partial" if partial or unresolved else "complete",
            "graph": "unknown",
            "environment": (
                "unknown"
                if any(record["disposition"] == "unsupported" for record in inputs.values())
                else (
                    "conditional-unknown"
                    if any(r["activation"] == "unknown" for r in occurrences) or any(r["marker"] for r in declarations)
                    else "unconditional"
                )
            ),
        },
    }
    source.validate()
    return {
        "schema_version": VERSION,
        "inventory_status": "partial" if partial or unresolved else "complete",
        "sbom_status": "not-run",
        "matching_status": "not-run",
        "packages": sorted({record["package"] for record in occurrences}),
        "edges": [],
        "application_identities": [],
        "semantic_dimensions": dimensions,
        "coverage": "prototype-pip-only",
        "refusal_codes": sorted(set(refusal_codes)),
        "budgets": {
            "status": "proposed-not-frozen",
            "source": asdict(source.limits),
            "occurrences": MAX_OCCURRENCES,
            "semantic_records_per_dimension": MAX_OCCURRENCES,
            "resolution_steps": MAX_RESOLUTION_STEPS,
            "include_depth": MAX_INCLUDE_DEPTH,
            "include_targets_per_root": MAX_INCLUDE_TARGETS,
        },
    }
