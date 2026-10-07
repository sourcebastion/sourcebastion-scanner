"""Canonical Go minimum declarations, never selected MVS packages or edges."""

from pathlib import PurePosixPath

from . import go_sources
from .contract import (
    AnalysisScope,
    Application,
    Declaration,
    InputCoverage,
    Locator,
    Occurrence,
    ProjectionLoss,
    Root,
    identifier,
    package_purl,
)
from .inputs import InputRefusal

VERSION = "sourcebastion.go-composition/1"

# The helper reports only directive kinds, never replacement targets or spans.
# Preserve that uncertainty at the source-file level without inventing details.
CONTROL_DIMENSIONS = {
    "duplicate-go-requirement": "version",
    "unassessed-replace-directive": "version",
    "unassessed-exclude-directive": "version",
    "unassessed-retract-directive": "version",
    "unassessed-toolchain-directive": "environment",
    "unassessed-tool-directive": "scope",
    "unassessed-godebug-directive": "environment",
    "unassessed-ignore-directive": "graph",
}


def extend(state, runtime):
    for row in sorted(state.result.inputs, key=lambda value: value.path):
        state.step()
        if row.format not in {"go-mod", "go-sum"} or row.disposition == "ignored" or row.sha256 is None:
            continue
        state.unresolved_versions = True
        state.graph = "partial"
        item = state.source.read(row.path)
        if item.sha256 != row.sha256:
            raise InputRefusal("changed-go-source-input")
        if row.format == "go-sum":
            state.inputs[row.path] = InputCoverage(
                source_path=row.path,
                source_sha256=row.sha256,
                format=row.format,
                parser=VERSION,
                disposition="unsupported",
                reason="unassessed-go-checksum-history",
            )
            continue
        document = go_sources.parse(
            item.content,
            runtime=runtime,
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
        if document.observation is None:
            continue
        state.enumerated = True
        state.unresolved_versions = True
        state.graph = "partial"
        observation = document.observation

        def locate(value):
            return Locator(path=row.path, source_sha256=row.sha256, locator=value, parser=VERSION)

        origin = locate("module-input")

        def loss(source, dimension, reason, occurrence_id=None):
            values = dict(source=source, dimension=dimension, reason=reason, occurrence_id=occurrence_id)
            state.retain(
                state.losses,
                ProjectionLoss(id=identifier("loss", {**values, "source": source.model_dump()}), **values),
            )

        for reason in observation.unassessed_directives:
            loss(origin, CONTROL_DIMENSIONS[reason], reason)
        scope = AnalysisScope(id=identifier("scope", origin.model_dump()), kind="manifest-input", source=origin)
        state.retain(state.scopes, scope)
        state.mark_context(row.path, scope.id)
        root = Root(id=identifier("root", origin.model_dump()), path=str(PurePosixPath(row.path).parent), source=origin)
        state.retain(state.roots, root)
        state.root_contexts[row.path].add(root.id)
        values = dict(root_id=root.id, source=origin, ecosystem="golang", name=observation.module, version=None)
        state.retain(
            state.applications,
            Application(id=identifier("application", {**values, "source": origin.model_dump()}), **values),
        )
        for raw in observation.requirements:
            state.step()
            source = locate(f"require[{raw.ordinal}]:line[{raw.line}]:bytes[{raw.start_byte}:{raw.end_byte}]")
            values = dict(
                source=source,
                kind="requirement",
                ecosystem="golang",
                name=raw.name,
                declared_range=raw.minimum_version,
                exact_version=None,
                root_id=root.id,
                analysis_scope_id=scope.id,
                scopes=("unknown",),
            )
            declaration = Declaration(id=identifier("declaration", {**values, "source": source.model_dump()}), **values)
            state.retain(state.declarations, declaration)
            values = dict(
                source=source,
                ecosystem="golang",
                name=raw.name,
                purl=package_purl("golang", raw.name, None),
                evidence_kind="declared",
                selected_version=None,
                declared_range=raw.minimum_version,
                root_id=root.id,
                analysis_scope_id=scope.id,
                directness="unknown",
                scopes=("unknown",),
                activation="unknown",
            )
            occurrence = Occurrence(id=identifier("occurrence", {**values, "source": source.model_dump()}), **values)
            state.retain(state.occurrences, occurrence, state.limits.occurrences)
            if raw.indirect:
                # A source annotation is not a resolved graph/directness proof.
                loss(source, "graph", "unassessed-go-indirect-annotation", occurrence.id)
