"""Exact pnpm snapshot references with separate importer/document scopes.

Importer paths are source analysis contexts, not inferred application roots.
Every graph endpoint is an admitted key in the same document; peer variants
remain separate occurrences even when their identities/purls are equal.
"""

from collections import defaultdict, deque

from . import npm_selectors, pnpm_sources
from .contract import (
    AnalysisScope,
    ContentHash,
    Declaration,
    DependencySelector,
    InputCoverage,
    Locator,
    Occurrence,
    Relationship,
    identifier,
    package_purl,
)
from .inputs import InputRefusal

VERSION = "sourcebastion.pnpm-composition/1"


def extend(state):
    for row in sorted(state.result.inputs, key=lambda value: value.path):
        state.step()
        if row.format != "pnpm-lock" or row.disposition == "ignored" or row.sha256 is None:
            continue
        item = state.source.read(row.path)
        if item.sha256 != row.sha256:
            raise InputRefusal("changed-pnpm-source-input")
        result = pnpm_sources.parse(
            item.content,
            deadline=state.source.deadline,
            check=state.step,
            max_records=min(
                max(0, 100000 - len(state.declarations)), max(0, state.limits.occurrences - len(state.occurrences))
            ),
        )
        if result.disposition == "bounded-omission":
            raise InputRefusal(result.reason)
        state.inputs[row.path] = InputCoverage(
            source_path=row.path,
            source_sha256=row.sha256,
            format=row.format,
            parser=result.parser,
            disposition=result.disposition,
            reason=result.reason,
        )
        if result.disposition == "parsed":
            state.adapted_inputs.add(row.path)
        if not result.documents:
            continue
        state.enumerated = True
        state.graph = "partial"

        def locate(locator):
            return Locator(path=row.path, source_sha256=row.sha256, locator=locator, parser=VERSION)

        def scope_for(locator):
            source = locate(locator)
            scope = AnalysisScope(id=identifier("scope", source.model_dump()), kind="lock-input", source=source)
            state.retain(state.scopes, scope)
            state.mark_context(row.path, scope.id)
            return scope

        for document in result.documents:
            state.step()
            if document.disposition not in {"parsed", "unsupported"}:
                continue
            # Strict maintained grammar admits every source-selected version.
            answers = npm_selectors.evaluate(
                [(value.version, "*") for value in document.packages],
                deadline=state.source.deadline,
                check=state.step,
            )
            packages = {}
            for raw, answer in zip(document.packages, answers):
                state.step()
                if answer == "invalid-version":
                    state.mark_unresolved((row.path,), "unsupported-pnpm-selected-version")
                else:
                    packages[raw.key] = raw
            adjacent = defaultdict(set)
            planned = defaultdict(list)
            for parent, raw in packages.items():
                state.step()
                for reference in raw.references:
                    state.step()
                    target = reference.name + "@" + reference.selected if reference.selected is not None else None
                    child = packages.get(target)
                    reason = reference.reason or ("pnpm-source-endpoint-not-admitted" if child is None else None)
                    if child is not None:
                        adjacent[parent].add(target)
                    planned[parent].append((reference, target, reason))

            def publish(scope, keys, direct, scopes_by_key, ranges_by_key, importer_bound):
                state.step()
                occurrences = {}
                for key in sorted(keys):
                    state.step()
                    raw = packages[key]
                    hashes = tuple(
                        ContentHash(algorithm=algorithm, digest=digest, kind="integrity")
                        for algorithm, digest in raw.hashes
                    )
                    ranges = ranges_by_key[key]
                    values = dict(
                        source=locate(raw.locator),
                        ecosystem="npm",
                        name=raw.name,
                        purl=package_purl("npm", raw.name, raw.version),
                        selected_version=raw.version,
                        evidence_kind="locked",
                        declared_range=next(iter(ranges)) if len(ranges) == 1 else None,
                        hashes=hashes,
                        registry_source_sha256=raw.source_key,
                        lock_optional=raw.optional,
                        analysis_scope_id=scope.id,
                        root_id=None,
                        directness="direct" if key in direct else "transitive" if importer_bound else "unknown",
                        scopes=tuple(sorted(scopes_by_key[key])) or ("unknown",),
                        activation="unknown",
                    )
                    occurrence = Occurrence(
                        id=identifier(
                            "occurrence",
                            {
                                **values,
                                "source": values["source"].model_dump(),
                                "hashes": [value.model_dump() for value in hashes],
                                "environment_sha256": state.environment.sha256,
                            },
                        ),
                        **values,
                    )
                    state.retain(state.occurrences, occurrence, state.limits.occurrences)
                    occurrences[key] = occurrence
                for parent_key in sorted(keys):
                    state.step()
                    for reference, target, reason in planned[parent_key]:
                        state.step()
                        child = occurrences.get(target) if reason is None else None
                        reason = reason or ("pnpm-source-context-endpoint-not-admitted" if child is None else None)
                        values = dict(
                            source=locate(reference.locator),
                            parent_id=occurrences[parent_key].id,
                            child_id=child.id if child else None,
                            ecosystem="npm",
                            name=reference.name,
                            exact_version=child.selected_version if child else None,
                            dialect="npm-semver-7.8.5",
                            marker_semantics="none",
                            scopes=(reference.scope,),
                            disposition="resolved" if child else "unresolved",
                            reason="unique-source-endpoint" if child else reason,
                            activation="unknown",
                        )
                        selector = DependencySelector(
                            id=identifier(
                                "selector",
                                {
                                    **values,
                                    "source": values["source"].model_dump(),
                                },
                            ),
                            **values,
                        )
                        state.retain(state.dependency_selectors, selector, state.limits.relationships)
                        if child is None:
                            state.mark_unresolved((row.path,), reason)
                        else:
                            values = dict(
                                selector_id=selector.id,
                                parent_id=selector.parent_id,
                                child_id=child.id,
                                source=selector.source,
                                evidence_status="evidenced",
                                scopes=selector.scopes,
                                activation="unknown",
                            )
                            state.retain(
                                state.relationships,
                                Relationship(
                                    id=identifier(
                                        "relationship",
                                        {
                                            **values,
                                            "source": selector.source.model_dump(),
                                        },
                                    ),
                                    **values,
                                ),
                                state.limits.relationships,
                            )

            # Each importer owns a source analysis context. No manifest/folder
            # pairing or application identity is guessed from its path.
            all_reachable = set()
            for importer in document.importers:
                state.step()
                scope = scope_for(importer.locator)
                queries, selections = [], []
                for reference in importer.references:
                    state.step()
                    target = reference.name + "@" + reference.selected if reference.selected is not None else None
                    child = packages.get(target)
                    queries.append((child.version if child else "0.0.0", reference.declared_range or ""))
                    selections.append((reference, target, child))
                answers = npm_selectors.evaluate(queries, deadline=state.source.deadline, check=state.step)
                direct, scopes_by_key, ranges_by_key = set(), defaultdict(set), defaultdict(set)
                for (reference, target, child), answer in zip(selections, answers):
                    state.step()
                    safe_range = (
                        reference.declared_range or None if answer not in {"invalid-range", "invalid-version"} else None
                    )
                    selected = child is not None and reference.reason is None and answer == "match"
                    values = dict(
                        source=locate(reference.locator),
                        kind="requirement",
                        ecosystem="npm",
                        name=reference.name,
                        declared_range=safe_range,
                        exact_version=child.version if selected else None,
                        scopes=(reference.scope,),
                        analysis_scope_id=scope.id,
                    )
                    declaration = Declaration(
                        id=identifier("declaration", {**values, "source": values["source"].model_dump()}), **values
                    )
                    state.retain(state.declarations, declaration)
                    if selected:
                        direct.add(target)
                        scopes_by_key[target].add(reference.scope)
                        if safe_range is not None:
                            ranges_by_key[target].add(safe_range)
                    else:
                        state.mark_unresolved((row.path,), reference.reason or "unresolved-pnpm-importer-selection")
                reachable, pending = set(direct), deque(sorted(direct))
                # Scopes propagate through evidenced source edges to a fixed
                # point. Explicit optional edges remain optional, not runtime.
                while pending:
                    state.step()
                    parent = pending.popleft()
                    for reference, target, reason in planned[parent]:
                        state.step()
                        if reason is not None:
                            continue
                        propagated = {"optional"} if reference.scope == "optional" else scopes_by_key[parent]
                        changed = not propagated.issubset(scopes_by_key[target])
                        scopes_by_key[target].update(propagated)
                        if target not in reachable or changed:
                            reachable.add(target)
                            pending.append(target)
                all_reachable.update(reachable)
                publish(scope, reachable, direct, scopes_by_key, ranges_by_key, True)
            remaining = set(packages) - all_reachable
            if remaining or not document.importers:
                scope = scope_for("documents[" + str(document.ordinal) + "]/unowned-snapshots")
                # Close this unowned analysis context over exact source edges.
                # A package also reached by an importer gets a separate local
                # occurrence; cross-context identity equality is never a join.
                pending = deque(sorted(remaining))
                while pending:
                    state.step()
                    for target in sorted(adjacent[pending.popleft()]):
                        state.step()
                        if target not in remaining:
                            remaining.add(target)
                            pending.append(target)
                publish(scope, remaining, set(), defaultdict(set), defaultdict(set), False)
