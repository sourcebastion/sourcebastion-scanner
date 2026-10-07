"""Provider observations must not acquire canonical authority by normalization."""

import copy
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from sourcebastion.inventory.discovery import discover
from sourcebastion.inventory.inputs import InputRefusal, Source
from sourcebastion.inventory.provider import ProviderReceipt, bind_provider

SHA = "a" * 64
FIXTURE = Path(__file__).parent / "fixtures/inventory-provider/npm-installed.json"
FILES = {
    "package-lock.json": '{"name": "probe-app", "version": "1.0.0", "lockfileVersion": 3, "packages": {"": {"name": "probe-app", "version": "1.0.0", "dependencies": {"debug": "^4.3.7"}}, "node_modules/debug": {"version": "4.3.7", "dependencies": {"ms": "^2.1.3"}}, "node_modules/ms": {"version": "2.1.3"}}}',
    "package.json": '{"name": "probe-app", "version": "1.0.0", "dependencies": {"debug": "^4.3.7"}}',
    "requirements.txt": "pip==26.0.1\n",
    "site-packages/pip-26.0.1.dist-info/METADATA": "Metadata-Version: 2.1\nName: pip\nVersion: 26.0.1\n",
}


def setup(root):
    for name, text in FILES.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def document():
    return json.loads(FIXTURE.read_bytes())


def run(root, value=None, *, raw=None, callback=lambda: None):
    setup(root)
    before = {name: (root / name).read_bytes() for name in FILES}
    raw = raw if raw is not None else json.dumps(value if value is not None else document()).encode()
    with Source(root) as source:
        found = discover(source)
        result = bind_provider(raw, source, found, source_sha256=SHA, provider_binary_sha256=SHA, check=callback)
    assert before == {name: (root / name).read_bytes() for name in FILES}
    return result


def test_real_provider_shapes_retain_roles_raw_references_and_unknown_authority(tmp_path):
    result = run(tmp_path)
    assert len(result.candidates) == 5 and len(result.dependencies) == 2
    assert result.coverage == "unassessed"
    assert {row.role for row in result.candidates} == {"lock-candidate", "installed-candidate", "package-metadata"}
    app = [row for row in result.candidates if row.name == "probe-app"]
    assert len(app) == 2 and len({row.raw_id for row in app}) == 2
    assert {row.bindings[0].path for row in app} == {"package.json", "package-lock.json"}
    # A lock root artifact remains unassessed, never a selected dependency.
    assert all(row.canonical_semantics == "unassessed" for row in app)
    assert all(row.role != "declaration-candidate" for row in result.candidates)
    installed = next(row for row in result.candidates if row.role == "installed-candidate")
    assert installed.purl == "pkg:pypi/pip@26.0.1"
    assert installed.bindings[0].source_sha256 == hashlib.sha256(FILES[installed.bindings[0].path].encode()).hexdigest()
    debug = next(row for row in result.candidates if row.name == "debug")
    ms = next(row for row in result.candidates if row.name == "ms")
    assert any(row.parent_raw_id == debug.raw_id and row.child_raw_id == ms.raw_id for row in result.dependencies)
    assert all(row.canonical_semantics == "unassessed" for row in result.dependencies)
    encoded = result.model_dump_json()
    assert ProviderReceipt.model_validate_json(encoded) == result
    assert "raw_metadata" not in encoded and "node_modules" not in encoded and 'dependencies":{"ms' not in encoded


def test_raw_customer_metadata_and_host_paths_remain_only_in_sidecar(tmp_path):
    value = document()
    value["artifacts"][0]["metadata"]["resolved"] = "https://alice:secret-token@packages.invalid/pkg"
    value["source"]["metadata"] = {"path": "/private/controller/customer-checkout"}
    result = run(tmp_path, value)
    encoded = result.model_dump_json()
    assert "secret-token" not in encoded and "customer-checkout" not in encoded
    assert (
        result.candidates[0].reference.raw_record_sha256
        == hashlib.sha256(json.dumps(value["artifacts"][0], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d["descriptor"].update(name="syft"),
        lambda d: d["schema"].update(version="16.2.0"),
        lambda d: d["source"].update(type="image"),
        lambda d: d["descriptor"]["configuration"]["data-generation"].update({"generate-cpes": True}),
        lambda d: d["descriptor"]["configuration"]["catalogers"]["used"].append("python-package-cataloger"),
        lambda d: d["descriptor"]["configuration"]["packages"]["golang"].update({"use-packages-lib": True}),
        lambda d: d["descriptor"]["configuration"]["packages"]["java-archive"].update({"use-network": True}),
        lambda d: d["artifacts"][0].update(cpes=["cpe:2.3:a:debug:debug:4.3.7:*:*:*:*:*:*:*"]),
        lambda d: d["artifacts"].append(copy.deepcopy(d["artifacts"][0])),
        lambda d: d["artifacts"][0].update(foundBy="python-package-cataloger"),
        lambda d: d["artifacts"][0].update(foundBy=[]),
        lambda d: d["artifacts"][0].update(type="python"),
        lambda d: d["files"][0]["digests"][0].update(value="b" * 64),
        lambda d: d["files"][0]["metadata"].update(size=999),
        lambda d: d["files"][0].update(location=[]),
        lambda d: d["files"].append(copy.deepcopy(d["files"][0])),
        lambda d: d["artifacts"][0]["locations"][0].update(path="/../package-lock.json"),
        lambda d: d["artifacts"][0]["locations"][0].update(path="//package-lock.json"),
        lambda d: d["artifacts"][0]["locations"][0].update(accessPath="/alias/package-lock.json"),
        lambda d: d["artifacts"][0]["locations"][0].update(path="/requirements.txt", accessPath="/requirements.txt"),
        lambda d: d["artifactRelationships"][0].update(parent="f" * 16),
        lambda d: d["artifactRelationships"][0].update(parent=[]),
        lambda d: d["artifactRelationships"][0].update(child={}),
        lambda d: d["artifactRelationships"][0].update(type=[]),
        lambda d: d["artifacts"][0].update(metadataType="arbitrary-other-schema"),
    ],
)
def test_invalid_observation_never_returns_partial_receipt(tmp_path, mutation):
    value = document()
    mutation(value)
    with pytest.raises(InputRefusal):
        run(tmp_path, value)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"x":1,"x":2}',
        b'{"x":NaN}',
        b'{"x":1e999}',
        b'{"x":"\\ud800"}',
        b"\xff",
        b"[" * 33 + b"0" + b"]" * 33,
        b'{"x":"' + b"x" * (2 * 1024 * 1024 + 1) + b'"}',
        '{"x":1}'.encode("utf-16"),
        b"null",
        b"",
    ],
)
def test_bounded_strict_json_refusals(tmp_path, raw):
    with pytest.raises(InputRefusal):
        run(tmp_path, raw=raw)


def test_raw_identity_does_not_guess_version_or_publish_unsafe_qualifiers(tmp_path):
    value = document()
    value["artifacts"][0].update(version="^4.3.7", purl="pkg:npm/debug@%5E4.3.7")
    result = run(tmp_path, value)
    assert result.candidates[0].identity_status == "unassessed"
    assert result.candidates[0].name is result.candidates[0].purl is result.candidates[0].observed_version is None


@pytest.mark.parametrize("name", ["a\x7fsecret-token", "a\x85secret-token", "a" * 513])
def test_untrusted_identity_validation_never_exposes_raw_input(tmp_path, name):
    from urllib.parse import quote

    value = document()
    value["artifacts"][0].update(name=name, version="1.0.0", purl="pkg:npm/" + quote(name, safe="") + "@1.0.0")
    result = run(tmp_path, value)
    assert result.candidates[0].identity_status == "unassessed"
    assert name not in result.model_dump_json() and "secret-token" not in result.model_dump_json()


def test_untrusted_source_path_validation_returns_only_fixed_code(tmp_path):
    name = "a\x7fsecret-token/package-lock.json"
    setup(tmp_path)
    path = tmp_path / name
    path.parent.mkdir()
    path.write_text(FILES["package-lock.json"])
    value = document()
    value["files"][0]["location"]["path"] = "/" + name
    with Source(tmp_path) as source:
        found = discover(source)
        with pytest.raises(InputRefusal) as caught:
            bind_provider(
                json.dumps(value).encode(),
                source,
                found,
                source_sha256=SHA,
                provider_binary_sha256=SHA,
                check=lambda: None,
            )
    assert str(caught.value) == "provider-receipt-validation-refused"
    assert "secret-token" not in str(caught.value)
    import traceback

    assert "secret-token" not in "".join(traceback.format_exception(caught.value))


def test_explicit_versionless_metadata_keeps_unknown_version(tmp_path):
    value = document()
    app = next(row for row in value["artifacts"] if row["foundBy"] == "javascript-package-cataloger")
    app.update(version="", purl="pkg:npm/probe-app")
    result = run(tmp_path, value)
    row = next(row for row in result.candidates if row.cataloger == "javascript-package-cataloger")
    assert row.observed_version is None and row.identity_status == "version-unreported"


def test_shared_semantic_callback_refuses_without_a_new_allowance(tmp_path):
    calls = 0

    def check():
        nonlocal calls
        calls += 1
        if calls > 10:
            raise InputRefusal("composition-check-budget-exceeded")

    with pytest.raises(InputRefusal, match="composition-check-budget-exceeded"):
        run(tmp_path, callback=check)
    assert calls == 11


def test_late_source_epoch_change_refuses_all_observations(tmp_path):
    setup(tmp_path)
    with Source(tmp_path) as source:
        found = discover(source)
        original = source.validate

        def changed():
            (tmp_path / "package.json").write_text("{}")
            original()

        source.validate = changed
        with pytest.raises(InputRefusal, match="changed-"):
            bind_provider(
                FIXTURE.read_bytes(), source, found, source_sha256=SHA, provider_binary_sha256=SHA, check=lambda: None
            )


def test_discovery_cannot_bind_a_provider_read_outside_its_admission(tmp_path):
    from sourcebastion.inventory.registry import DiscoveryConfig

    setup(tmp_path)
    with Source(tmp_path) as source:
        found = discover(source, config=DiscoveryConfig(ignored=("package-lock.json",)))
        with pytest.raises(InputRefusal, match="provider-source-hash-mismatch"):
            bind_provider(
                FIXTURE.read_bytes(), source, found, source_sha256=SHA, provider_binary_sha256=SHA, check=lambda: None
            )


def test_receipt_schema_rejects_reference_rebinding_and_dangling_edges(tmp_path):
    result = run(tmp_path)
    for change in [
        {"provider_output_sha256": "b" * 64},
        {"dependencies": (result.dependencies[0].model_copy(update={"parent_raw_id": "f" * 16}),)},
        {"candidates": result.candidates + (result.candidates[0],)},
    ]:
        with pytest.raises(ValidationError):
            ProviderReceipt.model_validate(result.model_copy(update=change))
