"""Source-selected Yarn descriptors, with no equal-package fallback."""

from collections import defaultdict

from . import npm_selectors, yarn_sources
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

VERSION = "sourcebastion.yarn-composition/1"


def extend(state):
    for row in sorted(state.result.inputs, key=lambda value: value.path):
        state.step()
        if row.format != "yarn-lock" or row.disposition == "ignored" or row.sha256 is None:
            continue
        item = state.source.read(row.path)
        if item.sha256 != row.sha256:
            raise InputRefusal("changed-yarn-source-input")
        document = yarn_sources.parse(
            item.content,
            deadline=state.source.deadline,
            check=state.step,
            max_records=max(0, state.limits.occurrences - len(state.occurrences)),
        )
        if document.disposition == "bounded-omission":
            raise InputRefusal(document.reason)
        state.inputs[row.path] = InputCoverage(
            source_path=row.path,
            source_sha256=row.sha256,
            format=row.format,
            parser=document.parser,
            disposition=document.disposition,
            reason=document.reason,
        )
        if document.disposition == "parsed":
            state.adapted_inputs.add(row.path)
        if document.disposition not in {"parsed", "unsupported"}:
            continue
        state.enumerated = True
        state.graph = "partial"

        def locate(locator):
            return Locator(path=row.path, source_sha256=row.sha256, locator=locator, parser=VERSION)

        scope_source = locate("lock-input")
        scope = AnalysisScope(id=identifier("scope", scope_source.model_dump()), kind="lock-input", source=scope_source)
        state.retain(state.scopes, scope)
        state.mark_context(row.path, scope.id)
        queries = []
        ordinals = []
        for raw in document.packages:
            state.step()
            version_query = len(queries)
            queries.append((raw.version, "*"))
            aliases = []
            for descriptor, expression in raw.descriptors:
                state.step()
                aliases.append((descriptor, len(queries)))
                queries.append((raw.version, expression))
                if len(queries) > 100000:
                    raise InputRefusal("yarn-selector-input-budget-exceeded")
            ordinals.append((raw, version_query, aliases))
        answers = npm_selectors.evaluate(queries, deadline=state.source.deadline, check=state.step)
        packages = {}
        alias_owners = defaultdict(set)
        for raw, version_ordinal, aliases in ordinals:
            state.step()
            if answers[version_ordinal] == "invalid-version":
                state.mark_unresolved((row.path,), "unsupported-yarn-selected-version")
                continue
            if not any(
                answers[ordinal] not in {"invalid-range", "invalid-version"} for _descriptor, ordinal in aliases
            ):
                state.mark_unresolved((row.path,), "unsupported-yarn-package-identity")
                continue
            packages[raw.key] = raw
            for descriptor, ordinal in aliases:
                state.step()
                if answers[ordinal] == "match":
                    alias_owners[descriptor].add(raw.key)
                else:
                    state.mark_unresolved((row.path,), "unsupported-yarn-source-descriptor")
        aliases = {}
        for descriptor, owners in alias_owners.items():
            state.step()
            if len(owners) == 1 and descriptor not in document.blocked_descriptors:
                aliases[descriptor] = next(iter(owners))
            else:
                state.mark_unresolved((row.path,), "ambiguous-yarn-source-descriptor")
        planned = []
        queries = []
        for parent, raw in packages.items():
            state.step()
            for reference in raw.references:
                state.step()
                if len(planned) >= state.limits.relationships - len(state.dependency_selectors):
                    raise InputRefusal("composition-record-budget-exceeded")
                target = aliases.get(reference.descriptor) if reference.scope != "peer" else None
                child = packages.get(target)
                reason = (
                    "unsupported-yarn-dependency-protocol"
                    if not reference.protocol_supported
                    else (
                        "yarn-peer-context-unassessed"
                        if reference.scope == "peer"
                        else "yarn-source-endpoint-not-admitted" if child is None else None
                    )
                )
                queries.append((child.version if child else "0.0.0", reference.expression))
                planned.append((parent, reference, target, reason, len(queries) - 1))
        answers = npm_selectors.evaluate(queries, deadline=state.source.deadline, check=state.step)
        occurrences = {}
        for key, raw in packages.items():
            state.step()
            hashes = tuple(
                ContentHash(algorithm=algorithm, digest=digest, kind="integrity") for algorithm, digest in raw.hashes
            )
            values = dict(
                source=locate(raw.locator),
                ecosystem="npm",
                name=raw.name,
                purl=package_purl("npm", raw.name, raw.version),
                selected_version=raw.version,
                evidence_kind="locked",
                hashes=hashes,
                registry_source_sha256=raw.source_key,
                root_id=None,
                analysis_scope_id=scope.id,
                directness="unknown",
                scopes=("unknown",),
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
        for parent, reference, target, reason, ordinal in planned:
            state.step()
            answer = answers[ordinal]
            if answer in {"invalid-range", "invalid-version"}:
                reason = "unsupported-yarn-dependency-selector"
            elif reason is None and answer != "match":
                reason = "yarn-selector-version-mismatch"
            child = occurrences.get(target) if reason is None else None
            values = dict(
                source=locate(reference.locator),
                parent_id=occurrences[parent].id,
                child_id=child.id if child else None,
                ecosystem="npm",
                name=reference.name,
                declared_range=(
                    (reference.expression or None)
                    if reference.protocol_supported and answer not in {"invalid-range", "invalid-version"}
                    else None
                ),
                dialect="npm-semver-7.8.5",
                marker_semantics="none",
                exact_version=child.selected_version if child else None,
                scopes=(reference.scope, "optional") if reference.optional else (reference.scope,),
                disposition="resolved" if child else "unresolved",
                reason="unique-source-endpoint" if child else reason,
                activation="unknown",
            )
            selector = DependencySelector(
                id=identifier("selector", {**values, "source": values["source"].model_dump()}), **values
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
                        id=identifier("relationship", {**values, "source": selector.source.model_dump()}), **values
                    ),
                    state.limits.relationships,
                )
