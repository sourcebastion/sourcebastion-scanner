"""Source-bound Gradle selections; configurations do not prove graph/ownership."""

from . import gradle_locks
from .contract import AnalysisScope, InputCoverage, Locator, Occurrence, ProjectionLoss, identifier, package_purl
from .inputs import InputRefusal

VERSION = "sourcebastion.gradle-composition/1"


def extend(state):
    for row in sorted(state.result.inputs, key=lambda value: value.path):
        state.step()
        if row.format != "gradle-lock" or row.disposition == "ignored" or row.sha256 is None:
            continue
        item = state.source.read(row.path)
        if item.sha256 != row.sha256:
            raise InputRefusal("changed-gradle-source-input")
        document = gradle_locks.parse(
            item.content,
            check=state.step,
            max_records=max(0, state.limits.occurrences - len(state.occurrences)),
        )
        state.inputs[row.path] = InputCoverage(
            source_path=row.path,
            source_sha256=row.sha256,
            format=row.format,
            parser=gradle_locks.VERSION,
            disposition=document.disposition,
            reason=document.reason,
        )
        if document.disposition != "parsed":
            state.unresolved_versions = True
            continue
        state.adapted_inputs.add(row.path)
        state.enumerated = True

        def locate(value):
            return Locator(path=row.path, source_sha256=row.sha256, locator=value, parser=VERSION)

        origin = locate("lock-input")
        scope = AnalysisScope(id=identifier("scope", origin.model_dump()), kind="lock-input", source=origin)
        state.retain(state.scopes, scope)
        state.mark_context(row.path, scope.id)
        if document.empty_configurations:
            values = dict(
                source=locate(f"line:{document.empty_line}"),
                dimension="scope",
                reason="unassessed-empty-gradle-configurations",
            )
            state.retain(
                state.losses,
                ProjectionLoss(id=identifier("loss", {**values, "source": values["source"].model_dump()}), **values),
            )
        for package in document.packages:
            state.step()
            name = f"{package.group}/{package.artifact}"
            source = locate(f"line:{package.line}")
            values = dict(
                source=source,
                ecosystem="maven",
                name=name,
                purl=package_purl("maven", name, package.version),
                evidence_kind="locked",
                selected_version=package.version,
                root_id=None,
                analysis_scope_id=scope.id,
                directness="unknown",
                scopes=package.configurations,
                activation="unknown",
            )
            state.retain(
                state.occurrences,
                Occurrence(
                    id=identifier(
                        "occurrence",
                        {**values, "source": source.model_dump(), "environment_sha256": state.environment.sha256},
                    ),
                    **values,
                ),
                state.limits.occurrences,
            )
