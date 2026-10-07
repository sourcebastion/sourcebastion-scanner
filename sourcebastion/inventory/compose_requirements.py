"""Compose one S02 discovery into located, source-evidenced pip inventory.

Requirements origins are analysis scopes, not projects inferred from folders.
Constraints remain declarations and include references never become dependency
edges. Selected versions come only from compatible exact source evidence.
This adapter does not implement other formats, a resolver or matching.
"""

from __future__ import annotations

from collections import defaultdict
import re
from types import SimpleNamespace

from packaging.specifiers import SpecifierSet
from packaging.version import Version
from pydantic import ValidationError

from .contract import (
    AnalysisScope,
    ContentHash,
    Coverage,
    Declaration,
    Environment,
    InputCoverage,
    InputReference,
    Inventory,
    InventoryLimits,
    Locator,
    Occurrence,
    Producer,
    StageStates,
    identifier,
    package_purl,
    _preflight_structure,
)
from .discovery import discover
from .inputs import InputRefusal, Source, relative_path
from .markers import context_key, disjoint, marker_activation
from .registry import DiscoveryConfig, REGISTRY_SHA256, format_for

VERSION = "sourcebastion.requirements-composition/1"
MAX_RECORDS = 100000


def _source_limits(source, config):
    return InventoryLimits(
        traversal_entries=source.limits.entries,
        traversal_depth=source.limits.depth,
        source_file_bytes=source.limits.file_bytes,
        parsed_text_bytes=source.limits.total_bytes,
        pipeline_wall_seconds=float(source.limits.wall_seconds),
        include_depth=config.include_depth,
        include_targets_per_origin=config.include_targets,
        semantic_checks=config.semantic_checks,
    )


def _origins(documents, step):
    """Source SCCs own their reachable includes, even for wholly cyclic input.

    Iterative Kosaraju avoids source-controlled Python recursion. Choosing a
    lexicographic remaining file instead would promote descendants of cycles.
    Every node/edge visit consumes the same bounded semantic ledger.
    """
    graph, reverse = {}, defaultdict(set)
    candidates = set()
    for path, document in documents.items():
        step()
        if document.disposition == "parsed" or document.references:
            candidates.add(path)
        children = set()
        for reference in document.references:
            step()
            if reference.target in documents:
                children.add(reference.target)
                reverse[reference.target].add(path)
        graph[path] = children
    seen, finished = set(), []
    for start in sorted(graph):
        step()
        if start in seen:
            continue
        seen.add(start)
        stack = [(start, iter(sorted(graph[start])))]
        while stack:
            step()
            node, children = stack[-1]
            try:
                child = next(children)
            except StopIteration:
                finished.append(node)
                stack.pop()
                continue
            if child not in seen:
                seen.add(child)
                stack.append((child, iter(sorted(graph[child]))))
    component, members = {}, []
    for start in reversed(finished):
        step()
        if start in component:
            continue
        number, group, pending = len(members), [], [start]
        component[start] = number
        while pending:
            step()
            node = pending.pop()
            group.append(node)
            for parent in reverse[node]:
                step()
                if parent not in component:
                    component[parent] = number
                    pending.append(parent)
        members.append(group)
    incoming = set()
    for parent, children in graph.items():
        for child in children:
            step()
            if component[parent] != component[child]:
                incoming.add(component[child])
    origins = []
    for number, group in enumerate(members):
        step()
        eligible = sorted(set(group) & candidates)
        if number not in incoming and eligible:
            origins.append(eligible[0])
    return sorted(origins)


def _compose(source, *, source_sha256, producer, environment=None, config=None, limits=None, manifest_inputs=False):
    """Consume a controller Source once; publish only after final epoch checks.

    The controller supplies admitted source/producer identities and the outer
    shared resource boundary. The emitted limits are assertions, not proof of
    kernel enforcement. No application DSN, source execution or network is used.
    """
    if not isinstance(source, Source):
        raise TypeError("controller-bound Source required")
    if not isinstance(source_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", source_sha256):
        raise ValueError("invalid-controller-source-digest")
    producer = Producer.model_validate(producer)
    environment = Environment.model_validate(environment if environment is not None else Environment())
    config = config if config is not None else DiscoveryConfig()
    if not isinstance(config, DiscoveryConfig):
        raise TypeError("validated DiscoveryConfig required")
    if producer.registry_sha256 != REGISTRY_SHA256 or producer.config_sha256 != config.sha256:
        raise ValueError("producer-discovery-config-mismatch")
    expected_limits = _source_limits(source, config)
    limits = InventoryLimits.model_validate(limits if limits is not None else expected_limits)
    for key in (
        "traversal_entries",
        "traversal_depth",
        "source_file_bytes",
        "parsed_text_bytes",
        "pipeline_wall_seconds",
        "include_depth",
        "include_targets_per_origin",
        "semantic_checks",
    ):
        if getattr(limits, key) != getattr(expected_limits, key):
            raise ValueError("source-discovery-limit-mismatch")

    result = discover(source, config=config)
    inputs = {}
    global_refusals = set(result.refusal_codes)
    for row in result.inputs:
        try:
            inputs[row.path] = InputCoverage(
                source_path=row.path,
                source_sha256=row.sha256,
                format=row.format,
                parser=row.parser,
                disposition=row.disposition,
                reason=row.reason,
            )
        except ValidationError:
            # An unrepresentable source path cannot become an invented located
            # record. Preserve global failed coverage and admit no packages.
            global_refusals.add("unrepresentable-input-coverage")
    scopes, declarations, references, occurrences = [], [], [], []
    context_ids = defaultdict(set)
    # Evidence is deduplicated; only the actual S02 visit counter preserves
    # shared accounting when requirement/constraint paths converge.
    checks = result.semantic_checks

    def step(count=1):
        nonlocal checks
        checks += count
        source.check()
        if checks > limits.semantic_checks:
            raise InputRefusal("composition-check-budget-exceeded")

    def retain(collection, item, maximum=MAX_RECORDS):
        step()
        if len(collection) >= maximum:
            raise InputRefusal("composition-record-budget-exceeded")
        collection.append(item)

    def locate(path, locator):
        covered = inputs.get(path)
        if covered is None or covered.source_sha256 is None:
            raise InputRefusal("unbound-composition-source")
        return Locator(path=path, source_sha256=covered.source_sha256, locator=locator, parser=VERSION)

    def mark_context(path, scope_id):
        if len(context_ids[path]) >= 4096 and scope_id not in context_ids[path]:
            raise InputRefusal("coverage-context-budget-exceeded")
        context_ids[path].add(scope_id)

    def mark_unresolved(paths, reason):
        for path in paths:
            step()
            row = inputs[path]
            if row.disposition == "parsed":
                inputs[path] = row.model_copy(update={"disposition": "unresolved", "reason": reason})

    marker_keys = {}

    def marker_key(value):
        if value not in marker_keys:
            step()
            marker_keys[value] = context_key(value, check=step)
        return marker_keys[value]

    def build_failed(reason):
        global_refusals.add(reason)
        return Inventory(
            source_sha256=source_sha256,
            producer=producer,
            limits=limits,
            environment=environment,
            environment_sha256=environment.sha256,
            coverage=Coverage(
                discovery="failed" if result.status == "failed" or reason.startswith("changed-") else "partial",
                enumeration="failed",
                version_resolution="unknown",
                graph="unknown",
                environment="unknown",
                inputs=tuple(inputs[path] for path in sorted(inputs)),
                refusal_codes=tuple(sorted(global_refusals)),
            ),
            stages=StageStates(inventory="failed"),
        )

    try:
        if checks > limits.semantic_checks:
            raise InputRefusal("composition-check-budget-exceeded")
        if result.status == "failed" or "unrepresentable-input-coverage" in global_refusals:
            return build_failed("discovery-evidence-not-admitted")
        documents = {doc.path: doc for doc in result.documents}
        contexts, origin_refs = defaultdict(list), defaultdict(list)
        for origin, path, role in result.contexts:
            step()
            contexts[origin].append((path, role))
        for reference in result.references:
            step()
            origin_refs[reference.origin].append(reference)
        origins = _origins(documents, step)
        claimed = set()
        had_requirement = False
        selection_nodes = 0
        for origin in origins:
            step()
            if origin in claimed:
                continue
            document = documents[origin]
            source_locator = locate(origin, "origin")
            scope = AnalysisScope(
                id=identifier("scope", ["requirements-origin", source_locator.model_dump()]),
                kind="requirements-origin",
                source=source_locator,
            )
            retain(scopes, scope)
            visited = contexts.get(origin, [(origin, "requirement")])
            affected = {path for path, _role in visited if path in inputs}
            claimed.update(path for path, _role in visited)
            local_failure = None
            for reference in origin_refs[origin]:
                step()
                target = reference.target
                if target in documents:
                    claimed.add(target)
                if target is not None:
                    try:
                        if relative_path(target) != target:
                            target = None
                    except InputRefusal:
                        target = None
                if target is not None and target not in inputs:
                    if len(inputs) >= MAX_RECORDS:
                        raise InputRefusal("composition-record-budget-exceeded")
                    inputs[target] = InputCoverage(
                        source_path=target,
                        source_sha256=None,
                        format=format_for(target, config),
                        parser=None,
                        disposition=reference.disposition,
                        reason=reference.reason,
                    )
                target_row = inputs.get(target)
                values = dict(
                    source=locate(reference.source, "line:" + str(reference.line)),
                    analysis_scope_id=scope.id,
                    kind=reference.kind,
                    role=reference.role,
                    target_path=target,
                    target_sha256=target_row.source_sha256 if target_row is not None else None,
                    disposition=reference.disposition,
                    reason=reference.reason,
                )
                retain(
                    references,
                    InputReference(
                        id=identifier("input-reference", {**values, "source": values["source"].model_dump()}), **values
                    ),
                )
                if reference.disposition != "parsed":
                    local_failure = local_failure or (
                        "ignored-required-reference" if reference.disposition == "ignored" else reference.reason
                    )
                if target is not None:
                    mark_context(target, scope.id)
            required, constraints = [], []
            for path, role in visited:
                step()
                if path not in inputs:
                    local_failure = local_failure or "missing-context-input"
                    continue
                mark_context(path, scope.id)
                child = documents.get(path)
                if child is None or child.disposition != "parsed":
                    local_failure = local_failure or (child.reason if child else "missing-context-input")
                    continue
                for record in child.requirements:
                    step()
                    values = dict(
                        source=locate(path, "line:" + str(record.line)),
                        kind=role,
                        ecosystem="pypi",
                        name=record.name,
                        declared_range=record.specifier or None,
                        exact_version=str(Version(record.exact_version)) if record.exact_version is not None else None,
                        marker=record.marker,
                        extras=record.extras,
                        analysis_scope_id=scope.id,
                        hashes=tuple(
                            ContentHash(algorithm=h.split(":")[0], digest=h.split(":")[1], kind="artifact")
                            for h in record.hashes
                        ),
                    )
                    payload = {
                        **values,
                        "source": values["source"].model_dump(),
                        "hashes": [h.model_dump() for h in values["hashes"]],
                    }
                    declaration = Declaration(id=identifier("declaration", payload), **values)
                    retain(declarations, declaration)
                    retain(constraints if role == "constraint" else required, declaration)
                    if role == "constraint" and record.extras:
                        local_failure = local_failure or "invalid-constraint-extras"
            had_requirement = had_requirement or bool(required)
            required_groups, constraint_names = defaultdict(list), defaultdict(list)
            for declaration in required:
                step()
                required_groups[(declaration.name, marker_key(declaration.marker))].append(declaration)
            for declaration in constraints:
                step()
                constraint_names[declaration.name].append(declaration)
            groups_by_name = defaultdict(list)
            for key, members in required_groups.items():
                step()
                groups_by_name[key[0]].append((key, members[0], {row.declared_range for row in members}))
            for groups in groups_by_name.values():
                for index, (_key, left, left_ranges) in enumerate(groups):
                    for _other, right, right_ranges in groups[index + 1 :]:
                        step()
                        if left.marker is not None and right.marker is not None and left_ranges != right_ranges:
                            if not disjoint(left.marker, right.marker, check=step):
                                local_failure = local_failure or "overlapping-marker-context-unresolved"
            selections = {}
            for key, members in required_groups.items():
                step()
                marker = members[0].marker
                evidence = list(members)
                if marker is not None:
                    evidence.extend(required_groups.get((key[0], marker_key(None)), ()))
                for constraint in constraint_names[key[0]]:
                    step()
                    if constraint.marker is None or marker_key(constraint.marker) == key[1]:
                        evidence.append(constraint)
                    elif not disjoint(marker, constraint.marker, check=step):
                        local_failure = local_failure or "conditional-constraint-unresolved"
                # Duplicate source lines remain declarations but share semantic
                # selection work and one representative per distinct contract.
                representatives = {}
                for declaration in evidence:
                    step()
                    signature = (
                        declaration.declared_range or "",
                        declaration.exact_version,
                        marker_key(declaration.marker),
                    )
                    previous = representatives.get(signature)
                    if previous is None or declaration.id < previous.id:
                        representatives[signature] = declaration
                unique_evidence = tuple(representatives.values())
                selectors = [
                    SpecifierSet(value) for value in sorted({row.declared_range or "" for row in unique_evidence})
                ]
                candidates_for_group = sorted(
                    {row.exact_version for row in unique_evidence if row.exact_version is not None}
                )
                compatible = []
                for candidate in candidates_for_group:
                    accepted = True
                    for selector in selectors:
                        step()
                        if not selector.contains(candidate, prereleases=True):
                            accepted = False
                            break
                    if accepted:
                        compatible.append(candidate)
                if candidates_for_group and not compatible:
                    local_failure = local_failure or (
                        "constraint-conflict" if constraint_names[key[0]] else "conflicting-root-declarations"
                    )
                if len({Version(value) for value in compatible}) > 1:
                    local_failure = local_failure or "ambiguous-source-selection"
                selections[key] = (compatible, tuple(sorted(row.id for row in unique_evidence)))
            if local_failure:
                global_refusals.add(local_failure)
                mark_unresolved(affected, local_failure)
            for declaration in required:
                step()
                selected, evidence_ids = selections[(declaration.name, marker_key(declaration.marker))]
                version = (
                    None
                    if local_failure or not selected
                    else (declaration.exact_version if declaration.exact_version in selected else selected[0])
                )
                if version is not None:
                    # Reserve expansion and repeated structural range proof
                    # work BEFORE allocating a per-occurrence evidence set.
                    # One link is also at least one serialized structure node.
                    projected = len(evidence_ids) + 1
                    step(2 * projected)
                    if selection_nodes + projected > limits.export_nodes:
                        raise InputRefusal("composition-structure-budget-exceeded")
                    selection_nodes += projected
                    ids = tuple(sorted(set(evidence_ids) | {declaration.id}))
                else:
                    ids = ()
                if len(ids) > 4096:
                    raise InputRefusal("selection-evidence-budget-exceeded")
                activation = marker_activation(declaration.marker, environment, check=step)
                values = dict(
                    source=declaration.source,
                    ecosystem="pypi",
                    name=declaration.name,
                    purl=package_purl("pypi", declaration.name, version),
                    evidence_kind="declared",
                    selected_version=version,
                    declared_range=declaration.declared_range,
                    hashes=declaration.hashes,
                    analysis_scope_id=scope.id,
                    directness="unknown",
                    marker=declaration.marker,
                    extras=declaration.extras,
                    activation=activation.activation,
                    selection_declaration_ids=ids,
                )
                payload = {
                    **values,
                    "source": declaration.source.model_dump(),
                    "hashes": [h.model_dump() for h in declaration.hashes],
                    "environment_sha256": environment.sha256,
                }
                retain(occurrences, Occurrence(id=identifier("occurrence", payload), **values), limits.occurrences)
                if version is None:
                    mark_unresolved((declaration.source.path,), "no-selected-version")
            if not required:
                mark_unresolved(affected, "no-required-dependency-declaration")
        # Only built-in, reviewed adapters can extend this private state. No
        # customer config can supply code or an arbitrary parser callback.
        extra = SimpleNamespace(
            source=source,
            result=result,
            limits=limits,
            environment=environment,
            inputs=inputs,
            scopes=scopes,
            declarations=declarations,
            occurrences=occurrences,
            global_refusals=global_refusals,
            roots=[],
            applications=[],
            applicability=[],
            relationships=[],
            dependency_selectors=[],
            graph="unknown",
            root_contexts=defaultdict(set),
            adapted_inputs=set(),
            enumerated=False,
            selection_nodes=selection_nodes,
            step=step,
            retain=retain,
            locate=locate,
            mark_context=mark_context,
            mark_unresolved=mark_unresolved,
        )
        if manifest_inputs:
            from .compose_manifests import extend

            extend(extra)
            from .compose_locks import extend as extend_locks

            extend_locks(extra)
            from .compose_npm import extend as extend_npm

            extend_npm(extra)
        source.validate()
        covered = tuple(
            inputs[path].model_copy(
                update={
                    "analysis_scope_ids": tuple(sorted(context_ids[path])),
                    "root_ids": tuple(sorted(extra.root_contexts[path])),
                }
            )
            for path in sorted(inputs)
        )
        incomplete = bool(global_refusals) or any(row.disposition not in {"parsed", "ignored"} for row in covered)
        version_fidelity = "partial" if any(row.selected_version is None for row in occurrences) else "complete"
        enumeration = "partial" if incomplete else "complete" if had_requirement or extra.enumerated else "unknown"
        discovery_fidelity = "partial" if result.status == "partial" else "complete"
        if (
            extra.adapted_inputs
            and not result.refusal_codes
            and all(
                row.disposition in {"parsed", "ignored"} or row.path in extra.adapted_inputs for row in result.inputs
            )
            and all(row.disposition in {"parsed", "ignored"} for row in result.references)
        ):
            discovery_fidelity = "complete"
        status = "complete" if enumeration == version_fidelity == discovery_fidelity == "complete" else "partial"
        payload = dict(
            schema_version="sourcebastion.inventory/1",
            source_sha256=source_sha256,
            producer=producer,
            limits=limits,
            environment=environment,
            environment_sha256=environment.sha256,
            roots=tuple(extra.roots),
            installed_environments=(),
            relationships=tuple(extra.relationships),
            applications=tuple(extra.applications),
            losses=(),
            applicability=tuple(extra.applicability),
            dependency_selectors=tuple(extra.dependency_selectors),
            analysis_scopes=tuple(scopes),
            declarations=tuple(declarations),
            input_references=tuple(references),
            occurrences=tuple(occurrences),
            coverage=Coverage(
                discovery=discovery_fidelity,
                enumeration=enumeration,
                version_resolution=version_fidelity,
                graph=extra.graph,
                environment="unknown",
                inputs=covered,
                refusal_codes=tuple(sorted(global_refusals)),
            ),
            stages=StageStates(inventory=status),
        )
        # Refuse the typed structure before Inventory's nested revalidation
        # repeats compatibility checks or materializes a full output mapping.
        try:
            _preflight_structure(payload, limits.export_nodes, limits.export_depth, limits.export_string_bytes)
        except ValueError:
            raise InputRefusal("composition-structure-budget-exceeded") from None
        inventory = Inventory(**payload)
        source.check()
        return inventory
    except InputRefusal as refusal:
        return build_failed(refusal.reason)
    except (ValueError, RecursionError):
        # A typed/source selector that cannot be admitted grants no selected
        # package authority. Diagnostic code never includes source text.
        return build_failed("canonical-composition-refused")


def compose_requirements(source, *, source_sha256, producer, environment=None, config=None, limits=None):
    """Compose pip inputs only, retaining other formats as unsupported."""
    return _compose(
        source, source_sha256=source_sha256, producer=producer, environment=environment, config=config, limits=limits
    )
