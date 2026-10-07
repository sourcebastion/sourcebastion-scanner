"""Registry-only Python locks in one Source/epoch/semantic ledger.

Lock input scopes do not imply project ownership or installed reachability.
Selectors without a unique source endpoint remain typed unresolved evidence.
"""

from collections import defaultdict

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from . import python_locks, poetry_constraints
from .contract import (
    AnalysisScope,
    Applicability,
    ContentHash,
    DependencySelector,
    InputCoverage,
    Locator,
    Occurrence,
    Relationship,
    identifier,
    package_purl,
)
from .inputs import InputRefusal
from .markers import disjoint, marker_activation

VERSION = "sourcebastion.lock-composition/1"


def extend(state):
    admitted_records = 0
    for row in state.result.inputs:
        state.step()
        if row.format not in python_locks.FORMATS or row.disposition == "ignored" or row.sha256 is None:
            continue
        item = state.source.read(row.path)
        if item.sha256 != row.sha256:
            raise InputRefusal("changed-lock-input")
        document = python_locks.parse(
            row.path,
            item.content,
            row.format,
            deadline=state.source.deadline,
            max_records=min(100000 - admitted_records, max(0, state.limits.occurrences - len(state.occurrences))),
            check=state.step,
        )
        admitted_records += document.record_count
        state.source.check()
        if document.reason == "composition-check-budget-exceeded":
            raise InputRefusal(document.reason)
        disposition = {"malformed": "failed", "budget-exceeded": "bounded-omission"}.get(
            document.disposition, document.disposition
        )
        state.inputs[row.path] = InputCoverage(
            source_path=row.path,
            source_sha256=row.sha256,
            format=row.format,
            parser=document.parser,
            disposition=disposition,
            reason=document.reason,
        )
        if document.disposition != "parsed" and not document.packages:
            continue
        if document.disposition == "parsed":
            state.adapted_inputs.add(row.path)
        state.enumerated = True

        def locate(locator):
            return Locator(path=row.path, source_sha256=row.sha256, locator=locator, parser=VERSION)

        scope_source = locate("lock-input")
        scope = AnalysisScope(
            id=identifier("scope", ["lock-input", scope_source.model_dump()]), kind="lock-input", source=scope_source
        )
        state.retain(state.scopes, scope)
        state.mark_context(row.path, scope.id)
        dialect = "poetry-core-2.1.3" if row.format == "python-poetry-lock" else "pep440"

        def applicability(expression, locator, occurrence_id=None, kind="python-version", condition_dialect=None):
            state.step()
            source = locate(locator)
            values = dict(
                source=source,
                kind=kind,
                dialect=condition_dialect or dialect,
                expression=expression,
                analysis_scope_id=scope.id,
                occurrence_id=occurrence_id,
            )
            payload = {**values, "source": source.model_dump()}
            state.retain(state.applicability, Applicability(id=identifier("applicability", payload), **values))

        # These are separately located assertions, not a conjunction of PDM's
        # alternative targets, nor a Python version borrowed from this host.
        for locator, expression in document.environment:
            applicability(expression, locator)
        by_name = defaultdict(list)
        records = []
        for raw in document.packages:
            state.step()
            version = str(Version(raw.version))
            groups = (raw.scope.split(":", 1)[1],) if raw.scope.startswith("group:") else ()
            scopes = ("group",) if groups else (raw.scope,)
            hashes = []
            for supplied in raw.hashes:
                state.step()
                algorithm, digest = supplied.split(":", 1)
                hashes.append(ContentHash(algorithm=algorithm, digest=digest, kind="artifact"))
            # A false explicit marker can exclude an occurrence. Truth alone
            # does not prove group, root-Python or installation selection.
            marker = marker_activation(raw.marker, state.environment, check=state.step).activation
            activation = "inactive" if marker == "inactive" else "unknown"
            values = dict(
                source=locate(raw.locator),
                ecosystem="pypi",
                name=raw.name,
                purl=package_purl("pypi", raw.name, version),
                evidence_kind="locked",
                selected_version=version,
                declared_range=raw.declared_range,
                hashes=tuple(hashes),
                registry_source_sha256=raw.source_key,
                lock_optional=raw.optional,
                analysis_scope_id=scope.id,
                directness="unknown",
                scopes=scopes,
                groups=groups,
                marker=raw.marker,
                extras=raw.extras,
                activation=activation,
            )
            payload = {
                **values,
                "source": values["source"].model_dump(),
                "hashes": [h.model_dump() for h in hashes],
                "environment_sha256": state.environment.sha256,
            }
            occurrence = Occurrence(id=identifier("occurrence", payload), **values)
            state.retain(state.occurrences, occurrence, state.limits.occurrences)
            by_name[raw.name].append((raw, occurrence))
            records.append((raw, occurrence))
            if raw.requires_python is not None:
                applicability(raw.requires_python, raw.locator + ".requires-python", occurrence.id)
            for group in groups:
                applicability(group, raw.locator + ".group", occurrence.id, "group", "group-name")
        for variants in by_name.values():
            for index, (left, left_occurrence) in enumerate(variants):
                for right_index in range(index + 1, len(variants)):
                    right, right_occurrence = variants[right_index]
                    state.step()
                    if (
                        left_occurrence.scopes != right_occurrence.scopes
                        or left_occurrence.groups != right_occurrence.groups
                        or left.extras != right.extras
                    ):
                        continue
                    if row.format != "python-uv-lock" and disjoint(left.marker, right.marker, check=state.step):
                        continue
                    state.global_refusals.add("overlapping-lock-variants")
                    state.mark_unresolved((row.path,), "overlapping-lock-variants")
        if any(raw.dependencies for raw, _ in records):
            # The adapter retains source edges. Full project/installation graph
            # completeness is not established by a lock table alone.
            state.graph = "partial"
        for raw, parent in records:
            repeated = {}
            selector_groups = defaultdict(list)
            for index, pairs in enumerate(raw.dependencies):
                state.step()
                parsed = dict(pairs)
                selector_groups[(parsed["name"], tuple(sorted(parsed.get("extras", ()))))].append((index, parsed))
            for variants in selector_groups.values():
                for index, (left_index, left) in enumerate(variants):
                    for right_ordinal in range(index + 1, len(variants)):
                        right_index, right = variants[right_ordinal]
                        state.step()
                        left_marker = left.get("condition", left.get("marker"))
                        right_marker = right.get("condition", right.get("marker"))
                        if row.format != "python-uv-lock" and disjoint(left_marker, right_marker, check=state.step):
                            continue
                        reason = (
                            "duplicate-lock-dependency"
                            if left_marker == right_marker
                            else "repeated-lock-dependency-context"
                        )
                        repeated[left_index] = repeated[right_index] = reason
            for index, pairs in enumerate(raw.dependencies):
                state.step()
                selector = dict(pairs)
                name = selector["name"]
                exact = selector.get("exact_version", selector.get("version"))
                exact = str(Version(exact)) if exact is not None else None
                requirement = selector.get("declared_constraint", "==" + exact if exact is not None else None)
                selector_dialect = selector.get("dialect", "pep440")
                marker = selector.get("condition", selector.get("marker"))
                extras = tuple(sorted(selector.get("extras", ())))
                registry = selector.get("source")
                locator = selector.get("locator", raw.locator + f".dependencies[{index}]")
                universe = by_name.get(name, ())
                # Charge each candidate visit before constructing intermediates
                # or running a maintained constraint grammar. No quadratic
                # candidate expansion bypasses the shared ledger.
                state.step(len(universe))
                reason = repeated.get(index)
                if row.format == "python-uv-lock":
                    if (exact is None and len({r.version for r, _ in universe}) > 1) or (
                        registry is None and len({r.source_key for r, _ in universe}) > 1
                    ):
                        reason = "ambiguous-lock-dependency"
                candidates = []
                constraint = None
                if requirement not in {None, "", "*"}:
                    constraint = (
                        poetry_constraints.constraint(requirement)
                        if selector_dialect == "poetry-core-2.1.3"
                        else SpecifierSet(requirement)
                    )
                if reason is None:
                    for candidate_raw, candidate in universe:
                        state.step()
                        if exact is not None and Version(candidate.selected_version) != Version(exact):
                            continue
                        if registry is not None and candidate.registry_source_sha256 != registry:
                            continue
                        if constraint is not None:
                            state.step()
                            accepted = (
                                constraint.allows(poetry_constraints.version(candidate.selected_version))
                                if selector_dialect == "poetry-core-2.1.3"
                                else constraint.contains(candidate.selected_version, prereleases=True)
                            )
                            if not accepted:
                                continue
                        if row.format == "python-pdm-lock" and candidate.extras != extras:
                            continue
                        if raw.group is not None and candidate_raw.group != raw.group:
                            continue
                        candidates.append(candidate)
                child = candidates[0] if reason is None and len(candidates) == 1 else None
                if child is None:
                    reason = reason or ("missing-lock-dependency" if not candidates else "ambiguous-lock-dependency")
                    state.global_refusals.add(reason)
                    state.mark_unresolved((row.path,), reason)
                marker_semantics = "relative-to-lock-python" if row.format == "python-uv-lock" else "pep508"
                activation = "unknown"
                if marker_semantics == "pep508":
                    selected = marker_activation(marker, state.environment, check=state.step).activation
                    if (
                        selected == "inactive"
                        or parent.activation == "inactive"
                        or (child is not None and child.activation == "inactive")
                    ):
                        activation = "inactive"
                source = locate(locator)
                values = dict(
                    source=source,
                    parent_id=parent.id,
                    child_id=child.id if child else None,
                    name=name,
                    declared_range=requirement or None,
                    dialect=selector_dialect,
                    exact_version=exact,
                    registry_source_sha256=registry,
                    marker=marker,
                    marker_semantics=marker_semantics,
                    extra_selection="variant-exact" if row.format == "python-pdm-lock" else "requested",
                    extras=extras,
                    scopes=parent.scopes,
                    groups=parent.groups,
                    activation=activation,
                    disposition="resolved" if child else "unresolved",
                    reason=reason or "unambiguous-lock-selection",
                )
                payload = {**values, "source": source.model_dump()}
                record = DependencySelector(id=identifier("selector", payload), **values)
                state.retain(state.dependency_selectors, record, state.limits.relationships)
                if child is not None:
                    values = dict(
                        source=source,
                        parent_id=parent.id,
                        child_id=child.id,
                        selector_id=record.id,
                        evidence_status="evidenced",
                        scopes=record.scopes,
                        marker=marker,
                        extras=extras,
                        activation=activation,
                    )
                    payload = {**values, "source": source.model_dump()}
                    state.retain(
                        state.relationships,
                        Relationship(id=identifier("relationship", payload), **values),
                        state.limits.relationships,
                    )
