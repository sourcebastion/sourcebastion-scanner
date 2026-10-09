"""Source-bound NuGet selections without framework inheritance or restoration."""

from . import nuget_sources
from .contract import (
    AnalysisScope,
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

VERSION = "sourcebastion.nuget-composition/1"


def extend(state):
    for row in sorted(state.result.inputs, key=lambda value: value.path):
        state.step()
        if row.format != "nuget-lock" or row.disposition == "ignored" or row.sha256 is None:
            continue
        item = state.source.read(row.path)
        if item.sha256 != row.sha256:
            raise InputRefusal("changed-nuget-source-input")
        document = nuget_sources.parse(
            item.content,
            deadline=state.source.deadline,
            check=state.step,
            max_records=max(0, state.limits.occurrences - len(state.occurrences)),
        )
        state.inputs[row.path] = InputCoverage(
            source_path=row.path,
            source_sha256=row.sha256,
            format=row.format,
            parser=nuget_sources.VERSION,
            disposition=document.disposition,
            reason=document.reason,
        )
        if not document.targets:
            state.unresolved_versions = True
            continue
        if document.disposition == "parsed":
            state.adapted_inputs.add(row.path)
        state.enumerated = True
        state.graph = "partial"

        def locate(value):
            return Locator(path=row.path, source_sha256=row.sha256, locator=value, parser=VERSION)

        scopes, admitted = {}, {}
        for target in document.targets:
            state.step()
            source = locate("/dependencies/" + nuget_sources.pointer(target))
            scope = AnalysisScope(id=identifier("scope", source.model_dump()), kind="lock-input", source=source)
            state.retain(state.scopes, scope)
            state.mark_context(row.path, scope.id)
            scopes[target] = scope
        for raw in document.packages:
            state.step()
            source = locate(raw.locator)
            values = dict(
                source=source,
                ecosystem="nuget",
                name=raw.name,
                purl=package_purl("nuget", raw.name, raw.version),
                evidence_kind="locked",
                selected_version=raw.version,
                declared_range=raw.requested,
                hashes=tuple(
                    ContentHash(algorithm=algorithm, digest=digest, kind="integrity")
                    for algorithm, digest in raw.hashes
                ),
                analysis_scope_id=scopes[raw.target].id,
                directness=raw.directness,
                scopes=(raw.target,),
                activation="unknown",
            )
            payload = {
                **values,
                "source": source.model_dump(),
                "hashes": [h.model_dump() for h in values["hashes"]],
                "environment_sha256": state.environment.sha256,
            }
            occurrence = Occurrence(id=identifier("occurrence", payload), **values)
            state.retain(state.occurrences, occurrence, state.limits.occurrences)
            admitted[(raw.target, raw.name)] = occurrence
        for raw in document.packages:
            parent = admitted[(raw.target, raw.name)]
            for name, expression, pointer in raw.dependencies:
                state.step()
                candidate = admitted.get((raw.target, name))
                answer = None if candidate is None else nuget_sources.satisfies(candidate.selected_version, expression)
                reason = (
                    "missing-nuget-lock-endpoint"
                    if candidate is None
                    else (
                        "unassessed-nuget-dependency-range"
                        if answer is None
                        else "contradictory-nuget-dependency-range" if not answer else "source-nuget-lock-endpoint"
                    )
                )
                child = candidate if answer is True else None
                values = dict(
                    source=locate(raw.locator + "/dependencies/" + pointer),
                    parent_id=parent.id,
                    child_id=None if child is None else child.id,
                    ecosystem="nuget",
                    name=name,
                    declared_range=expression,
                    dialect="nuget-release-range-1",
                    marker_semantics="none",
                    scopes=(raw.target,),
                    disposition="unresolved" if child is None else "resolved",
                    reason=reason,
                )
                selector = DependencySelector(
                    id=identifier("selector", {**values, "source": values["source"].model_dump()}), **values
                )
                state.retain(state.dependency_selectors, selector, state.limits.relationships)
                if child is None:
                    state.mark_unresolved((row.path,), reason)
                else:
                    edge = dict(
                        selector_id=selector.id,
                        parent_id=parent.id,
                        child_id=child.id,
                        source=selector.source,
                        evidence_status="evidenced",
                        scopes=selector.scopes,
                        activation="unknown",
                    )
                    state.retain(
                        state.relationships,
                        Relationship(
                            id=identifier("relationship", {**edge, "source": edge["source"].model_dump()}), **edge
                        ),
                        state.limits.relationships,
                    )
