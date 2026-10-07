"""Source-aware npm composition sharing the existing reader and ledger.

Lock paths select endpoints; range checks only verify that source selection.
Peer, workspace and non-registry contexts never gain guessed endpoints.
"""

from collections import defaultdict, deque
import posixpath

from . import npm_sources, npm_selectors
from .contract import (
    AnalysisScope,
    Application,
    ContentHash,
    Declaration,
    DependencySelector,
    InputCoverage,
    Locator,
    Occurrence,
    Relationship,
    Root,
    identifier,
    package_purl,
)
from .inputs import InputRefusal

VERSION = "sourcebastion.npm-composition/1"


def _endpoint(entry, name, entries, step):
    # Node's ancestor node_modules search, using only explicit lock entries.
    # A present-but-refused entry blocks fallback to a different ancestor.
    prefix = entry
    while True:
        step()
        if posixpath.basename(prefix) != "node_modules":
            candidate = (prefix + "/" if prefix else "") + "node_modules/" + name
            if candidate in entries:
                return candidate
        if not prefix:
            return None
        prefix = posixpath.dirname(prefix)


def extend(state):
    manifests = defaultdict(list)
    # Source facts are not cached across calls or merged by package identity.
    for row in sorted(state.result.inputs, key=lambda row: (row.format != "npm-manifest", row.path)):
        state.step()
        if row.format not in npm_sources.FORMATS or row.disposition == "ignored" or row.sha256 is None:
            continue
        item = state.source.read(row.path)
        if item.sha256 != row.sha256:
            raise InputRefusal("changed-npm-source-input")
        document = npm_sources.parse(
            item.content,
            row.format,
            deadline=state.source.deadline,
            check=state.step,
            max_records=min(
                max(0, 100000 - len(state.declarations)), max(0, state.limits.occurrences - len(state.occurrences))
            ),
        )
        if document.disposition == "bounded-omission":
            # A bounded parser must not leave a falsely complete partial graph.
            raise InputRefusal(document.reason)
        state.inputs[row.path] = InputCoverage(
            source_path=row.path,
            source_sha256=row.sha256,
            format=row.format,
            parser=document.parser,
            disposition=document.disposition,
            reason=document.reason,
        )
        if document.disposition not in {"parsed", "unsupported"} or not (
            document.application or document.declarations or document.packages or document.disposition == "parsed"
        ):
            continue
        if document.disposition == "parsed":
            state.adapted_inputs.add(row.path)
        state.enumerated = True
        state.graph = "partial" if row.format == "npm-lock" else state.graph

        def locate(locator):
            return Locator(path=row.path, source_sha256=row.sha256, locator=locator, parser=VERSION)

        scope_source = locate("manifest-input" if row.format == "npm-manifest" else "lock-input")
        scope = AnalysisScope(
            id=identifier("scope", [row.format, scope_source.model_dump()]),
            kind="manifest-input" if row.format == "npm-manifest" else "lock-input",
            source=scope_source,
        )
        state.retain(state.scopes, scope)
        state.mark_context(row.path, scope.id)
        root_id = None
        application = document.application
        if application is not None and application[1] is not None:
            admitted_version = npm_selectors.evaluate(
                [(application[1], "*")], deadline=state.source.deadline, check=state.step
            )[0]
            if admitted_version == "invalid-version":
                application = None
                state.mark_unresolved((row.path,), "unsupported-npm-application-version")
        signature = tuple(sorted((raw.name, raw.expression, raw.scope, raw.optional) for raw in document.declarations))
        if application is not None:
            name, version = application
            candidates = (
                manifests.get((posixpath.dirname(row.path), name, version, signature), ())
                if row.format == "npm-lock"
                else ()
            )
            # Exact explicit application identity and all dependency tables must
            # agree. Folder proximity or equal purls alone never assigns roots.
            if len(candidates) == 1:
                root_id = candidates[0]
            else:
                app_source = locate("/name" if row.format == "npm-manifest" else "/packages//name")
                root = Root(
                    id=identifier("root", [app_source.model_dump(), name, version]),
                    path=posixpath.dirname(row.path) or ".",
                    source=app_source,
                )
                state.retain(state.roots, root)
                root_id = root.id
                state.retain(
                    state.applications,
                    Application(
                        id=identifier("application", [root_id, name, version]),
                        root_id=root_id,
                        source=app_source,
                        ecosystem="npm",
                        name=name,
                        version=version,
                    ),
                )
            state.root_contexts[row.path].add(root_id)
            if row.format == "npm-manifest":
                manifests[(posixpath.dirname(row.path), name, version, signature)].append(root_id)
        declarations = []
        # Bounded batches share the remaining outer deadline and work ledger.
        queries = []
        for raw in document.declarations:
            state.step()
            try:
                package_purl("npm", raw.name, raw.expression)
                exact = raw.expression
            except ValueError:
                exact = None
            if len(raw.expression) > 256:
                exact = None
            queries.append((exact or "0.0.0", raw.expression))
            declarations.append((raw, exact))
        for raw in document.packages:
            state.step()
            queries.append((raw.version, "*"))
        answers = npm_selectors.evaluate(queries, deadline=state.source.deadline, check=state.step)
        root_selectors = []
        for index, (raw, exact) in enumerate(declarations):
            state.step()
            answer = answers[index]
            if answer in {"invalid-range", "invalid-version"}:
                exact = None
                state.mark_unresolved((row.path,), "unsupported-npm-declaration-selector")
            values = dict(
                source=locate(raw.locator),
                kind="requirement",
                ecosystem="npm",
                name=raw.name,
                declared_range=raw.expression or None if answer not in {"invalid-range", "invalid-version"} else None,
                exact_version=exact,
                scopes=(raw.scope, "optional") if raw.optional else (raw.scope,),
                root_id=root_id,
                analysis_scope_id=scope.id,
            )
            declaration = Declaration(
                id=identifier("declaration", {**values, "source": values["source"].model_dump()}), **values
            )
            state.retain(state.declarations, declaration)
            if row.format == "npm-manifest":
                payload = dict(
                    source=declaration.source,
                    ecosystem="npm",
                    name=raw.name,
                    selected_version=exact,
                    purl=package_purl("npm", raw.name, exact),
                    evidence_kind="declared",
                    declared_range=declaration.declared_range,
                    selection_declaration_ids=(declaration.id,) if exact is not None else (),
                    root_id=root_id,
                    analysis_scope_id=scope.id,
                    directness="direct",
                    scopes=(raw.scope, "optional") if raw.optional else (raw.scope,),
                    activation="unknown",
                )
                occurrence = Occurrence(
                    id=identifier(
                        "occurrence",
                        {
                            **payload,
                            "source": payload["source"].model_dump(),
                            "environment_sha256": state.environment.sha256,
                        },
                    ),
                    **payload,
                )
                state.retain(state.occurrences, occurrence, state.limits.occurrences)
                if exact is None:
                    state.mark_unresolved((row.path,), "no-selected-version")
            else:
                root_selectors.append(raw)
        admitted = {}
        for index, raw in enumerate(document.packages, start=len(declarations)):
            state.step()
            if answers[index] == "invalid-version":
                state.mark_unresolved((row.path,), "unsupported-npm-selected-version")
                continue
            admitted[raw.entry] = raw
        # Plan source endpoint checks without ever scanning all equal names.
        planned = []
        queries = []
        for entry, raw in admitted.items():
            for selector in raw.selectors:
                state.step()
                if len(planned) >= state.limits.relationships - len(state.dependency_selectors):
                    raise InputRefusal("composition-record-budget-exceeded")
                endpoint = (
                    None if selector.scope == "peer" else _endpoint(entry, selector.name, document.entries, state.step)
                )
                child = admitted.get(endpoint)
                reason = (
                    "npm-peer-context-unassessed"
                    if selector.scope == "peer"
                    else "npm-source-endpoint-not-admitted" if child is None else None
                )
                # Validate every selector grammar, even when its endpoint is
                # absent/peer/refused. Unsupported URIs can contain credentials.
                if len(queries) >= 100000:
                    raise InputRefusal("npm-selector-input-budget-exceeded")
                ordinal = len(queries)
                queries.append((child.version if child is not None else "0.0.0", selector.expression))
                planned.append((entry, selector, endpoint, reason, ordinal))
        root_planned = []
        for selector in root_selectors:
            state.step()
            endpoint = None if selector.scope == "peer" else _endpoint("", selector.name, document.entries, state.step)
            child = admitted.get(endpoint)
            if len(queries) >= 100000:
                raise InputRefusal("npm-selector-input-budget-exceeded")
            ordinal = len(queries)
            queries.append((child.version if child is not None else "0.0.0", selector.expression))
            root_planned.append((selector, endpoint if child is not None else None, ordinal))
        answers = npm_selectors.evaluate(queries, deadline=state.source.deadline, check=state.step)
        direct, direct_ranges, adjacent = set(), defaultdict(set), defaultdict(set)
        for selector, endpoint, ordinal in root_planned:
            state.step()
            if endpoint is not None and answers[ordinal] == "match":
                direct.add(endpoint)
                direct_ranges[endpoint].add(selector.expression)
            else:
                state.mark_unresolved((row.path,), "unresolved-npm-root-selector")
        for parent, selector, child, reason, ordinal in planned:
            state.step()
            if reason is None and ordinal is not None and answers[ordinal] == "match":
                adjacent[parent].add(child)
        reachable, pending = set(direct), deque(sorted(direct))
        while pending:
            state.step()
            for child in sorted(adjacent[pending.popleft()]):
                state.step()
                if child not in reachable:
                    reachable.add(child)
                    pending.append(child)
        occurrences = {}
        for entry, raw in admitted.items():
            state.step()
            hashes = tuple(
                ContentHash(algorithm=algorithm, digest=digest, kind="integrity") for algorithm, digest in raw.hashes
            )
            ranges = direct_ranges[entry]
            values = dict(
                source=locate(raw.locator),
                ecosystem="npm",
                name=raw.name,
                purl=package_purl("npm", raw.name, raw.version),
                evidence_kind="locked",
                selected_version=raw.version,
                declared_range=next(iter(ranges)) or None if len(ranges) == 1 else None,
                hashes=hashes,
                registry_source_sha256=raw.source_key,
                lock_optional=raw.optional,
                root_id=root_id if entry in reachable else None,
                analysis_scope_id=scope.id,
                directness="direct" if entry in direct else "transitive" if entry in reachable else "unknown",
                scopes=raw.scopes,
                activation="unknown",
            )
            occurrence = Occurrence(
                id=identifier(
                    "occurrence",
                    {
                        **values,
                        "source": values["source"].model_dump(),
                        "hashes": [h.model_dump() for h in hashes],
                        "environment_sha256": state.environment.sha256,
                    },
                ),
                **values,
            )
            state.retain(state.occurrences, occurrence, state.limits.occurrences)
            occurrences[entry] = occurrence
        for parent_entry, raw, child_entry, reason, ordinal in planned:
            state.step()
            if answers[ordinal] in {"invalid-range", "invalid-version"}:
                reason = "unsupported-npm-dependency-selector"
            if reason is None and answers[ordinal] != "match":
                reason = (
                    "unsupported-npm-dependency-selector"
                    if answers[ordinal] == "invalid-range"
                    else "npm-selector-version-mismatch"
                )
            child = occurrences.get(child_entry) if reason is None else None
            parent = occurrences[parent_entry]
            values = dict(
                source=locate(raw.locator),
                parent_id=parent.id,
                child_id=child.id if child else None,
                ecosystem="npm",
                name=raw.name,
                declared_range=(
                    raw.expression or None if answers[ordinal] not in {"invalid-range", "invalid-version"} else None
                ),
                dialect="npm-semver-7.8.5",
                marker_semantics="none",
                scopes=(raw.scope, "optional") if raw.optional else (raw.scope,),
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
                    parent_id=parent.id,
                    child_id=child.id,
                    source=selector.source,
                    evidence_status="evidenced",
                    scopes=selector.scopes,
                    activation="unknown",
                )
                relationship = Relationship(
                    id=identifier("relationship", {**values, "source": selector.source.model_dump()}), **values
                )
                state.retain(state.relationships, relationship, state.limits.relationships)
