"""Architectural joins preserve evidence ownership rather than package equality."""

from copy import deepcopy
import json

import pytest

from evaluation.m046.composition_spike import compose
from evaluation.m046.static_inputs import Source


def artifact(
    identifier,
    name="pip",
    version="26.0.1",
    path="site-packages/pip.dist-info/METADATA",
    cataloger="python-installed-package-cataloger",
    ecosystem="pypi",
    kind="python",
):
    return {
        "id": identifier,
        "name": name,
        "version": version,
        "purl": f"pkg:{ecosystem}/{name}" + (f"@{version}" if version else ""),
        "foundBy": cataloger,
        "type": kind,
        "cpes": [],
        "locations": [{"path": "/" + path}],
        "metadataType": "python-package",
        "metadata": {},
    }


def setup(tmp_path):
    files = {
        "a/requirements.txt": "pip==26.0.1\n",
        "b/requirements.txt": "pip==26.0.1\n",
        "site-packages/pip.dist-info/METADATA": "Metadata-Version: 2.1\nName: pip\nVersion: 26.0.1\nRequires-Dist: packaging>=24\n",
        "web/package.json": json.dumps({"name": "fixture", "version": "1.0.0"}),
        "web/package-lock.json": json.dumps({"lockfileVersion": 3}),
        "go/go.mod": "module example.test/fixture\nrequire example.test/dependency v1.0.0\n",
    }
    for path, content in files.items():
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    app = artifact("app", "fixture", "1.0.0", "web/package.json", "javascript-package-cataloger", "npm", "npm")
    app["metadataType"] = "javascript-npm-package"
    parent = artifact("parent", "debug", "4.3.7", "web/package-lock.json", "javascript-lock-cataloger", "npm", "npm")
    child = artifact("child", "ms", "2.1.3", "web/package-lock.json", "javascript-lock-cataloger", "npm", "npm")
    unselected = artifact(
        "unselected", "example.test/dependency", "", "go/go.mod", "go-module-file-cataloger", "golang", "go-module"
    )
    unselected["metadataType"] = "go-module-entry"
    declared = deepcopy(unselected)
    declared.update(id="declared", version="v1.0.0", purl="pkg:golang/example.test/dependency@v1.0.0")
    raw = {
        "descriptor": {"name": "m046-restricted-evidence-provider"},
        "artifacts": [artifact("installed"), app, parent, child, unselected, declared],
        "artifactRelationships": [{"type": "dependency-of", "parent": "child", "child": "parent"}],
    }
    return raw


def test_composition_keeps_duplicate_roots_and_source_installed_authorities(tmp_path):
    raw = setup(tmp_path)
    with Source(tmp_path) as source:
        result = compose(source, raw)
    assert [r["occurrence"]["root"] for r in result["source_occurrences"]] == ["a", "b"]
    assert len({r["id"] for r in result["source_occurrences"]}) == 2
    installed = next(r for r in result["provider_evidence"] if r["raw_provider_id"] == "installed")
    assert installed["id"] not in {r["id"] for r in result["source_occurrences"]}
    assert installed["role"] == "installed-version-evidence"
    assert installed["installed_environment"] is None
    assert installed["activation"] == "unknown"
    assert installed["record"]["identity"] == "pypi:pip@26.0.1"
    assert result["inventory_status"] == "partial" and not result["full_contract_qualified"]


def test_application_declaration_and_versionless_records_cannot_be_external_matches(tmp_path):
    raw = setup(tmp_path)
    with Source(tmp_path) as source:
        result = compose(source, raw)
    records = {r["raw_provider_id"]: r for r in result["provider_evidence"]}
    assert records["app"]["role"] == "application-metadata"
    assert records["declared"]["role"] == "declaration-candidate"
    assert records["unselected"]["role"] == "unselected-versionless-metadata"
    assert records["unselected"]["record"]["identity"] is None
    assert all(
        not records[key]["match_eligible_identity_evidence"]
        for key in ("app", "declared", "unselected", "parent", "child")
    )


def test_edge_keeps_raw_ids_paths_analysis_scope_and_unassessed_canonical_role(tmp_path):
    raw = setup(tmp_path)
    with Source(tmp_path) as source:
        result = compose(source, raw)
    edge = result["provider_relations"][0]
    assert (edge["parent_provider_id"], edge["child_provider_id"]) == ("parent", "child")
    assert edge["shared_evidence_paths"] == ["web/package-lock.json"]
    assert edge["analysis_scopes"] == ["web"]
    assert edge["canonical_edge"] == "unassessed" and edge["matching_edge"] is False
    assert edge["parent_evidence_id"] != edge["child_evidence_id"]


@pytest.mark.parametrize(
    "change",
    [
        "wrong-installed-version",
        "duplicate-installed-name",
        "wrong-application-version",
        "duplicate-application-name",
        "source-symlink",
    ],
)
def test_source_provider_disagreement_or_unsafe_source_refuses_composition(tmp_path, change):
    raw = setup(tmp_path)
    if change == "wrong-installed-version":
        (tmp_path / "site-packages/pip.dist-info/METADATA").write_text("Name: pip\nVersion: 99\n")
    elif change == "duplicate-installed-name":
        (tmp_path / "site-packages/pip.dist-info/METADATA").write_text("Name: pip\nName: other\nVersion: 26.0.1\n")
    elif change == "wrong-application-version":
        (tmp_path / "web/package.json").write_text('{"name":"fixture","version":"99"}')
    elif change == "duplicate-application-name":
        (tmp_path / "web/package.json").write_text('{"name":"other","name":"fixture","version":"1.0.0"}')
    else:
        path = tmp_path / "site-packages/pip.dist-info/METADATA"
        path.unlink()
        path.symlink_to(tmp_path / "a/requirements.txt")
    with Source(tmp_path) as source, pytest.raises((ValueError, OSError, RuntimeError)):
        compose(source, raw)


def test_provider_input_order_does_not_change_evidence_ids_or_source_occurrences(tmp_path):
    raw = setup(tmp_path)
    with Source(tmp_path) as source:
        first = compose(source, raw)
    raw["artifacts"].reverse()
    with Source(tmp_path) as source:
        second = compose(source, raw)
    assert first == second


@pytest.mark.parametrize(
    "change", ["raw-name", "raw-version", "invalid-name", "invalid-version", "wrong-type", "wrong-metadata-type"]
)
def test_invalid_or_contradictory_installed_identity_is_never_match_eligible(tmp_path, change):
    raw = setup(tmp_path)
    installed = raw["artifacts"][0]
    if change == "raw-name":
        installed["name"] = "different"
    elif change == "raw-version":
        installed["version"] = "99"
    elif change == "wrong-type":
        installed["type"] = "npm"
    elif change == "wrong-metadata-type":
        installed["metadataType"] = "javascript-npm-package"
    else:
        name, version = ("pip!", "26.0.1") if change == "invalid-name" else ("pip", "not-a-version")
        installed.update(name=name, version=version, purl=f"pkg:pypi/{name}@{version}")
        (tmp_path / "site-packages/pip.dist-info/METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
        )
    with Source(tmp_path) as source, pytest.raises(ValueError):
        compose(source, raw)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_nonfinite_json_never_receives_application_role(tmp_path, constant):
    raw = setup(tmp_path)
    (tmp_path / "web/package.json").write_text('{"name":"fixture","version":"1.0.0","extra":' + constant + "}")
    with Source(tmp_path) as source, pytest.raises(ValueError, match="nonfinite"):
        compose(source, raw)
