"""Canonical Cargo observations without build, resolution, or name-only joins."""

from collections import defaultdict
from pathlib import PurePosixPath
import hashlib
from . import cargo_sources
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

VERSION = "sourcebastion.cargo-composition/1"


def extend(state):
    for row in sorted(state.result.inputs, key=lambda value: value.path):
        state.step()
        if row.format not in {"cargo-lock", "cargo-manifest"} or row.disposition == "ignored" or row.sha256 is None:
            continue
        item = state.source.read(row.path)
        if item.sha256 != row.sha256:
            raise InputRefusal("changed-cargo-source-input")
        document = cargo_sources.parse(
            item.content,
            row.format,
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

        scope_source = locate("manifest-input" if row.format == "cargo-manifest" else "lock-input")
        scope = AnalysisScope(
            id=identifier("scope", scope_source.model_dump()),
            kind="manifest-input" if row.format == "cargo-manifest" else "lock-input",
            source=scope_source,
        )
        state.retain(state.scopes, scope)
        state.mark_context(row.path, scope.id)
        root_id = None
        if document.application is not None:
            project_source = locate("package")
            directory = str(PurePosixPath(row.path).parent)
            root = Root(id=identifier("root", project_source.model_dump()), path=directory, source=project_source)
            state.retain(state.roots, root)
            root_id = root.id
            state.root_contexts[row.path].add(root_id)
            values = dict(
                root_id=root_id,
                source=project_source,
                ecosystem="cargo",
                name=document.application[0],
                version=document.application[1],
            )
            state.retain(
                state.applications,
                Application(id=identifier("application", {**values, "source": project_source.model_dump()}), **values),
            )
        for raw in document.declarations:
            state.step()
            state.unresolved_versions = True
            values = dict(
                source=locate(raw.locator),
                kind="requirement",
                ecosystem="cargo",
                name=raw.name,
                declared_range=raw.expression,
                exact_version=None,
                marker=raw.condition,
                extras=raw.features,
                scopes=raw.scopes,
                root_id=root_id,
                analysis_scope_id=scope.id,
            )
            state.retain(
                state.declarations,
                Declaration(
                    id=identifier("declaration", {**values, "source": values["source"].model_dump()}), **values
                ),
            )
        occurrences = {}
        by_name = defaultdict(list)
        for raw in document.packages:
            state.step()
            by_name[raw.name].append(raw)
            if not raw.admitted:
                continue
            values = dict(
                source=locate(f"package[{raw.ordinal}]"),
                ecosystem="cargo",
                name=raw.name,
                purl=package_purl("cargo", raw.name, raw.version),
                evidence_kind="locked",
                selected_version=raw.version,
                hashes=tuple(
                    ContentHash(algorithm=algorithm, digest=digest, kind="artifact") for algorithm, digest in raw.hashes
                ),
                registry_source_sha256=hashlib.sha256(raw.source.encode()).hexdigest(),
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
                        "hashes": [value.model_dump() for value in values["hashes"]],
                        "environment_sha256": state.environment.sha256,
                    },
                ),
                **values,
            )
            state.retain(state.occurrences, occurrence, state.limits.occurrences)
            occurrences[raw.ordinal] = occurrence
        for parent in document.packages:
            if parent.ordinal not in occurrences:
                continue
            for ref in parent.dependencies:
                state.step()
                # Index only accelerates lookup. The serialized source selector
                # chooses among ALL entries, including refused identity blockers.
                candidates = []
                for target in by_name.get(ref.name, ()):
                    state.step()
                    if ref.version is not None and target.version != ref.version:
                        continue
                    if ref.source is not None and target.source != ref.source:
                        continue
                    candidates.append(target)
                target = candidates[0] if len(candidates) == 1 else None
                child = occurrences.get(target.ordinal) if target else None
                reason = (
                    "unique-source-endpoint"
                    if child
                    else (
                        "ambiguous-cargo-lock-selector" if len(candidates) > 1 else "cargo-source-endpoint-not-admitted"
                    )
                )
                values = dict(
                    source=locate(ref.locator),
                    parent_id=occurrences[parent.ordinal].id,
                    child_id=child.id if child else None,
                    ecosystem="cargo",
                    name=ref.name,
                    dialect="cargo-lock-package-id-3-4",
                    marker_semantics="none",
                    exact_version=child.selected_version if child else ref.version,
                    registry_source_sha256=hashlib.sha256(ref.source.encode()).hexdigest() if ref.source else None,
                    scopes=("unknown",),
                    activation="unknown",
                    disposition="resolved" if child else "unresolved",
                    reason=reason,
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
