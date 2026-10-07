"""Observed Python metadata with unknown ownership and no resolved child graph."""

from . import python_metadata
from .contract import AnalysisScope, Applicability, Declaration, InputCoverage, Locator, Occurrence, ProjectionLoss
from .contract import identifier, package_purl
from .inputs import InputRefusal
from packaging.version import Version

VERSION = "sourcebastion.metadata-composition/1"


def extend(state):
    for row in state.result.inputs:
        state.step()
        if row.format != "python-installed-metadata" or row.disposition == "ignored" or row.sha256 is None:
            continue
        item = state.source.read(row.path)
        if item.sha256 != row.sha256:
            raise InputRefusal("changed-metadata-input")
        document = python_metadata.parse(row.path, item.content, check=state.step)
        if document.disposition == "bounded-omission":
            raise InputRefusal(document.reason)
        state.inputs[row.path] = InputCoverage(
            source_path=row.path,
            source_sha256=row.sha256,
            format=row.format,
            parser=python_metadata.VERSION,
            disposition=document.disposition,
            reason=document.reason,
        )
        if document.name is None:
            continue
        state.adapted_inputs.add(row.path)
        state.enumerated = True
        # A METADATA file does not establish the complete installed dependency
        # graph, even when no Requires-Dist header is present.
        state.graph = "partial"

        def locate(value):
            return Locator(path=row.path, source_sha256=row.sha256, locator=value, parser=VERSION)

        source = locate("metadata-input")
        scope = AnalysisScope(id=identifier("scope", source.model_dump()), kind="manifest-input", source=source)
        state.retain(state.scopes, scope)
        state.mark_context(row.path, scope.id)
        source = locate("headers:Name,Version")
        values = dict(
            source=source,
            ecosystem="pypi",
            name=document.name,
            purl=package_purl("pypi", document.name, document.version),
            evidence_kind="installed",
            selected_version=document.version,
            analysis_scope_id=scope.id,
            scopes=("unknown",),
            activation="unknown",
        )
        occurrence = Occurrence(id=identifier("occurrence", {**values, "source": source.model_dump()}), **values)
        state.retain(state.occurrences, occurrence, state.limits.occurrences)

        def loss(source, dimension, reason):
            values = dict(source=source, dimension=dimension, reason=reason, occurrence_id=occurrence.id)
            state.retain(
                state.losses, ProjectionLoss(id=identifier("loss", {**values, "source": source.model_dump()}), **values)
            )

        loss(source, "environment", "installed-environment-unassessed")
        for field, ordinal, dimension, reason in document.losses:
            state.step()
            loss(locate(f"header:{field}[{ordinal}]"), dimension, reason)
        for ordinal, raw in enumerate(document.requirements):
            state.step()
            source = locate(f"header:Requires-Dist[{ordinal}]")
            values = dict(
                source=source,
                kind="requirement",
                ecosystem="pypi",
                name=raw.name,
                declared_range=raw.specifier or None,
                exact_version=str(Version(raw.exact_version)) if raw.exact_version is not None else None,
                marker=raw.marker,
                extras=raw.extras,
                scopes=("unknown",),
                analysis_scope_id=scope.id,
            )
            state.retain(
                state.declarations,
                Declaration(id=identifier("declaration", {**values, "source": source.model_dump()}), **values),
            )
        if document.requires_python is not None:
            source = locate("header:Requires-Python[0]")
            values = dict(
                source=source,
                kind="python-version",
                dialect="pep440",
                expression=document.requires_python,
                analysis_scope_id=scope.id,
                occurrence_id=occurrence.id,
            )
            state.retain(
                state.applicability,
                Applicability(id=identifier("applicability", {**values, "source": source.model_dump()}), **values),
            )
