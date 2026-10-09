"""Source-bound Ruby/PHP lock packages; graph/ownership remain unassessed."""

from . import secondary_locks
from .contract import AnalysisScope, InputCoverage, Locator, Occurrence, ProjectionLoss, identifier, package_purl
from .inputs import InputRefusal

VERSION = "sourcebastion.secondary-lock-composition/1"


def extend(state):
    for row in sorted(state.result.inputs, key=lambda value: value.path):
        state.step()
        if row.format not in secondary_locks.FORMATS or row.disposition == "ignored" or row.sha256 is None:
            continue
        item = state.source.read(row.path)
        if item.sha256 != row.sha256:
            raise InputRefusal("changed-secondary-lock-source")
        document = secondary_locks.parse(
            item.content,
            row.format,
            deadline=state.source.deadline,
            check=state.step,
            max_records=max(0, state.limits.occurrences - len(state.occurrences)),
        )
        state.inputs[row.path] = InputCoverage(
            source_path=row.path,
            source_sha256=row.sha256,
            format=row.format,
            parser=secondary_locks.VERSION,
            disposition=document.disposition,
            reason=document.reason,
        )
        if (
            document.disposition not in {"parsed", "unsupported"}
            or not document.packages
            and document.disposition != "parsed"
        ):
            state.unresolved_versions = True
            continue
        if document.disposition == "parsed":
            state.adapted_inputs.add(row.path)
        state.enumerated = True

        def locate(value):
            return Locator(path=row.path, source_sha256=row.sha256, locator=value, parser=VERSION)

        source = locate("lock-input")
        scope = AnalysisScope(id=identifier("scope", source.model_dump()), kind="lock-input", source=source)
        state.retain(state.scopes, scope)
        state.mark_context(row.path, scope.id)
        for raw in document.packages:
            state.step()
            ecosystem = secondary_locks.FORMATS[row.format]
            source = locate(raw.locator)
            values = dict(
                source=source,
                ecosystem=ecosystem,
                name=raw.name,
                selected_version=raw.version,
                purl=package_purl(ecosystem, raw.name, raw.version),
                evidence_kind="locked",
                registry_source_sha256=raw.registry_sha256,
                analysis_scope_id=scope.id,
                directness="unknown",
                scopes=raw.scopes,
                activation="unknown",
            )
            occurrence = Occurrence(
                id=identifier(
                    "occurrence",
                    {**values, "source": source.model_dump(), "environment_sha256": state.environment.sha256},
                ),
                **values,
            )
            state.retain(state.occurrences, occurrence, state.limits.occurrences)
            if raw.graph_locator:
                state.graph = "partial"
                loss = dict(
                    source=locate(raw.graph_locator),
                    occurrence_id=occurrence.id,
                    dimension="graph",
                    reason="unassessed-" + ("composer" if ecosystem == "composer" else "bundler") + "-dependency-graph",
                )
                state.retain(
                    state.losses,
                    ProjectionLoss(id=identifier("loss", {**loss, "source": loss["source"].model_dump()}), **loss),
                )
