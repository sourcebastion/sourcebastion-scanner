"""Mirror availability may fall back; reviewed pin errors may not."""

import io
import json
from pathlib import Path
import runpy
import sys
import urllib.error

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def selector(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return runpy.run_path(str(ROOT / "scripts/select_base_images.py"))


@pytest.mark.parametrize("payload", [b'[]', b'{"token":12}', b'bad-json'])
def test_malformed_anonymous_token_is_unavailable(monkeypatch, payload):
    tool = selector(monkeypatch)
    monkeypatch.setattr(tool["urllib"].request, "urlopen", lambda *a, **k: io.BytesIO(payload))
    assert tool["anonymous_token"]("ghcr.io", "sourcebastion/base-python") == ""


@pytest.mark.parametrize("available", [True, False])
def test_selection_uses_requested_checkout_pins_and_keeps_digest(monkeypatch, tmp_path, capsys, available):
    tool = selector(monkeypatch)
    for name in (".github/base-image-pins.json", "images/Dockerfile", "PYTHON_VERSION"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / name).read_bytes())
    # The baseline can have a different reviewed digest from the candidate.
    path = tmp_path / ".github/base-image-pins.json"
    pins = json.loads(path.read_text())
    old = pins["images"][0]["digest"]
    pins["images"][0]["digest"] = "sha256:" + "d" * 64
    path.write_text(json.dumps(pins))
    path = tmp_path / "images/Dockerfile"
    path.write_text(path.read_text().replace(old, pins["images"][0]["digest"]))
    scope = tool["main"].__globals__
    monkeypatch.setitem(scope, "serves", lambda image: available)
    monkeypatch.setattr(sys, "argv", ["select", "--checkout", str(tmp_path), "--format", "json"])
    assert tool["main"]() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["PYTHON_BASE"].endswith("@sha256:" + "d" * 64)
    assert result["PYTHON_BASE"].startswith("ghcr.io/" if available else "docker.io/")
    (tmp_path / "PYTHON_VERSION").write_text("3.14.9")
    with pytest.raises(ValueError, match="version-mismatch"):
        tool["main"]()


def test_public_ghcr_token_and_manifest_request(monkeypatch):
    tool = selector(monkeypatch)
    calls = []
    def open_(request, **kwargs):
        calls.append(request)
        response = io.BytesIO(b'{"token":"public-token"}')
        response.status = 200
        return response
    monkeypatch.setattr(tool["urllib"].request, "urlopen", open_)
    assert tool["serves"]({"mirror_repository": "ghcr.io/sourcebastion/base-python", "digest": "sha256:" + "a" * 64})
    assert "repository%3Asourcebastion%2Fbase-python%3Apull" in calls[0]
    assert calls[1].get_method() == "HEAD"
    assert calls[1].get_header("Authorization") == "Bearer public-token"


def test_registry_outage_is_unavailable(monkeypatch):
    tool = selector(monkeypatch)
    def unavailable(*args, **kwargs):
        raise urllib.error.URLError("registry unavailable")
    monkeypatch.setattr(tool["urllib"].request, "urlopen", unavailable)
    assert not tool["serves"]({"mirror_repository": "ghcr.io/sourcebastion/base-python", "digest": "sha256:" + "a" * 64})


def test_all_oci_builds_receive_their_own_reviewed_base_arguments():
    workflow = yaml.load((ROOT / ".github/workflows/docker.yml").read_text(), Loader=yaml.BaseLoader)
    steps = workflow["jobs"]["build-scanner"]["steps"]
    candidate = next(s["run"] for s in steps if s["name"].startswith("Retain candidate compressed"))
    baseline = next(s["run"] for s in steps if s["name"] == "Enforce added compressed release layers")
    assert "steps.bases.outputs.build_args" in candidate
    assert 'select_base_images.py --checkout "$base_dir"' in baseline
    assert baseline.count('"${base_args[@]}"') == 2


def test_release_preparation_stages_both_pin_manifests():
    workflow = yaml.load((ROOT / ".github/workflows/prepare-release.yml").read_text(), Loader=yaml.BaseLoader)
    step = next(s for s in workflow["jobs"]["prepare"]["steps"] if s.get("name") == "Open release PR for review and native image validation")
    assert ".github/base-image-pins.json .github/inventory-runtime-pins.json" in step["run"]
