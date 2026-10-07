"""Static manifest extension for the private, shared canonical composer.

No second traversal/discovery, source execution, host target or resolver.
"""

from collections import defaultdict
import posixpath

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from . import python_manifests
from .contract import (
    AnalysisScope,
    Application,
    Applicability,
    Declaration,
    Environment,
    InputCoverage,
    Locator,
    Occurrence,
    Root,
    identifier,
    package_purl,
)
from .inputs import InputRefusal
from .markers import context_key, disjoint, marker_activation

VERSION = "sourcebastion.manifest-composition/1"
FORMATS = frozenset({"python-pyproject", "python-setup-cfg", "python-setup-static"})


def extend(state):
    for row in state.result.inputs:
        state.step()
        # Discovery already read these exact bytes. Source.read reuses its
        # admitted cache; final controller epoch validation still follows.
        if row.format not in FORMATS or row.disposition == "ignored" or row.sha256 is None:
            continue
        item = state.source.read(row.path)
        if item.sha256 != row.sha256:
            raise InputRefusal("changed-manifest-input")
        document = python_manifests.parse(
            row.path,
            item.content,
            row.format,
            deadline=state.source.deadline,
            max_records=max(0, 100000 - len(state.declarations)),
        )
        state.source.check()
        disposition = {"malformed": "failed", "budget-exceeded": "bounded-omission"}.get(
            document.disposition, document.disposition
        )
        state.inputs[row.path] = InputCoverage(
            source_path=row.path,
            source_sha256=row.sha256,
            format=row.format,
            parser=document.parser,
            disposition=disposition,
            reason=document.reason,
        )
        if document.disposition != "parsed":
            continue
        state.adapted_inputs.add(row.path)

        def locate(locator):
            return Locator(path=row.path, source_sha256=row.sha256, locator=locator, parser=VERSION)

        source = locate("manifest-input")
        scope = AnalysisScope(
            id=identifier("scope", ["manifest-input", source.model_dump()]), kind="manifest-input", source=source
        )
        state.retain(state.scopes, scope)
        state.mark_context(row.path, scope.id)
        root_id = None
        if document.application is not None:
            name, raw_version = document.application.removeprefix("pypi:").rsplit("@", 1)
            version = str(Version(raw_version))
            app_source = locate("manifest-application")
            root = Root(
                id=identifier("root", [app_source.model_dump(), name, version]),
                path=posixpath.dirname(row.path) or ".",
                source=app_source,
            )
            state.retain(state.roots, root)
            root_id = root.id
            state.root_contexts[row.path].add(root_id)
            state.retain(
                state.applications,
                Application(
                    id=identifier("application", [root_id, name, version]),
                    root_id=root_id,
                    source=app_source,
                    ecosystem="pypi",
                    name=name,
                    version=version,
                ),
            )
        compatibility = "active"
        for locator, expression in document.environment:
            state.step()
            evidence = locate(locator)
            state.retain(
                state.applicability,
                Applicability(
                    id=identifier("applicability", [scope.id, evidence.model_dump(), expression]),
                    source=evidence,
                    kind="python-version",
                    dialect="pep440",
                    expression=expression,
                    root_id=root_id,
                    analysis_scope_id=scope.id,
                ),
            )
            full = state.environment.marker_environment.get("python_full_version")
            value = "unknown"
            if full is not None:
                state.step()
                value = "active" if SpecifierSet(expression).contains(full, prereleases=True) else "inactive"
            if compatibility != "inactive":
                compatibility = value
        declarations = []
        keyed = defaultdict(list)
        for raw in document.declarations:
            state.step()
            record = raw.requirement
            optional = raw.scope.startswith("optional:")
            groups = (raw.scope.split(":", 1)[1],) if optional else ()
            values = dict(
                source=locate(raw.locator),
                kind="requirement",
                ecosystem="pypi",
                name=record.name,
                declared_range=record.specifier or None,
                exact_version=str(Version(record.exact_version)) if record.exact_version is not None else None,
                marker=record.marker,
                extras=record.extras,
                scopes=("optional",) if optional else (raw.scope,),
                groups=groups,
                root_id=root_id,
                analysis_scope_id=scope.id,
            )
            payload = {**values, "source": values["source"].model_dump()}
            declaration = Declaration(id=identifier("declaration", payload), **values)
            state.retain(state.declarations, declaration)
            declarations.append(declaration)
            keyed[(record.name, declaration.scopes, groups)].append(declaration)
        selections = {}
        failure = None
        for _key, members in keyed.items():
            contexts = defaultdict(list)
            for declaration in members:
                state.step()
                contexts[context_key(declaration.marker, check=state.step)].append(declaration)
            variants = list(contexts.items())
            for index, (_left_key, left) in enumerate(variants):
                for _right_key, right in variants[index + 1 :]:
                    state.step()
                    if not disjoint(left[0].marker, right[0].marker, check=state.step):
                        failure = "overlapping-manifest-context-unresolved"
            for marker_key, same_context in variants:
                representatives = {}
                for declaration in same_context:
                    state.step()
                    signature = (declaration.declared_range, declaration.exact_version)
                    previous = representatives.get(signature)
                    if previous is None or declaration.id < previous.id:
                        representatives[signature] = declaration
                evidence = tuple(representatives.values())
                selectors = [SpecifierSet(d.declared_range or "") for d in evidence]
                candidates = sorted({d.exact_version for d in evidence if d.exact_version is not None})
                compatible = []
                for candidate in candidates:
                    accepted = True
                    for selector in selectors:
                        state.step()
                        if not selector.contains(candidate, prereleases=True):
                            accepted = False
                            break
                    if accepted:
                        compatible.append(candidate)
                if candidates and not compatible:
                    failure = "conflicting-manifest-declarations"
                if len({Version(value) for value in compatible}) > 1:
                    failure = "ambiguous-manifest-selection"
                selections[(_key, marker_key)] = (compatible, tuple(sorted(d.id for d in evidence)))
        if failure:
            state.global_refusals.add(failure)
            state.mark_unresolved((row.path,), failure)
        for declaration in declarations:
            state.step()
            key = (declaration.name, declaration.scopes, declaration.groups)
            marker_key = context_key(declaration.marker, check=state.step)
            selected, evidence_ids = selections[(key, marker_key)]
            version = (
                None
                if failure or not selected
                else (declaration.exact_version if declaration.exact_version in selected else selected[0])
            )
            ids = ()
            if version is not None:
                projected = len(evidence_ids) + 1
                state.step(2 * projected)
                if state.selection_nodes + projected > state.limits.export_nodes:
                    raise InputRefusal("composition-structure-budget-exceeded")
                state.selection_nodes += projected
                ids = tuple(sorted(set(evidence_ids) | {declaration.id}))
                if len(ids) > 4096:
                    raise InputRefusal("selection-evidence-budget-exceeded")
            # The project's explicit target does not bind the build host or
            # interpreter. Without a distinct build target, its markers keep
            # unknown inputs even when the project target is fully supplied.
            target = Environment() if declaration.scopes == ("build",) else state.environment
            activation = marker_activation(declaration.marker, target, check=state.step).activation
            # Requires-Python applies to the project's runtime/optional/test
            # declarations; build dependencies have a distinct interpreter.
            applicable = "active" if declaration.scopes == ("build",) else compatibility
            if activation != "inactive":
                if applicable == "inactive":
                    activation = "inactive"
                elif applicable == "unknown" or declaration.groups:
                    activation = "unknown"
            values = dict(
                source=declaration.source,
                ecosystem="pypi",
                name=declaration.name,
                purl=package_purl("pypi", declaration.name, version),
                evidence_kind="declared",
                selected_version=version,
                declared_range=declaration.declared_range,
                root_id=root_id,
                analysis_scope_id=scope.id,
                directness="direct",
                scopes=declaration.scopes,
                groups=declaration.groups,
                marker=declaration.marker,
                extras=declaration.extras,
                activation=activation,
                selection_declaration_ids=ids,
            )
            payload = {
                **values,
                "source": declaration.source.model_dump(),
                "environment_sha256": state.environment.sha256,
            }
            occurrence = Occurrence(id=identifier("occurrence", payload), **values)
            state.retain(state.occurrences, occurrence, state.limits.occurrences)
            for group in declaration.groups:
                state.step()
                state.retain(
                    state.applicability,
                    Applicability(
                        id=identifier("applicability", [occurrence.id, group]),
                        source=declaration.source,
                        kind="group",
                        dialect="group-name",
                        expression=group,
                        root_id=root_id,
                        analysis_scope_id=scope.id,
                        occurrence_id=occurrence.id,
                    ),
                )
            if version is None:
                state.mark_unresolved((row.path,), "no-selected-version")
        state.enumerated = state.enumerated or bool(declarations or document.application)
        if not declarations and document.application is None:
            state.mark_unresolved((row.path,), "no-project-dependency-evidence")
