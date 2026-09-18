from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_action_pins.py"
SPEC = importlib.util.spec_from_file_location("check_action_pins", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class FakeAPI:
    def __init__(self, overrides=None):
        self.overrides = overrides or {}

    def resolve_tag(self, action, version):
        pins = [
            pin
            for pin in MODULE.discover_pins()
            if (pin.action, pin.version) == (action, version)
        ]
        return self.overrides.get((action, version), pins[0].revision)


def test_audit_discovers_active_shipped_and_generated_references():
    paths = {pin.path.relative_to(ROOT).as_posix() for pin in MODULE.discover_pins()}
    assert any(path.startswith(".github/workflows/") for path in paths)
    assert "dashboard/.github/workflows/deploy-dashboard.yml" in paths
    assert "github/dashboard/update-assets.yml" in paths
    assert "github/templates/scan.yml" in paths
    assert "ez_appsec/org_manager.py" in paths


def test_matching_upstream_tags_pass():
    assert MODULE.audit(FakeAPI()) == []


def test_moved_tag_reports_every_stale_copy():
    first = MODULE.discover_pins()[0]
    replacement = "f" * 40 if first.revision != "f" * 40 else "e" * 40
    failures = MODULE.audit(FakeAPI({(first.action, first.version): replacement}))
    matching = [
        pin
        for pin in MODULE.discover_pins()
        if (pin.action, pin.version) == (first.action, first.version)
    ]
    assert len(failures) == len(matching)
    assert all("upstream tag resolves to" in failure for failure in failures)


def test_subdirectory_action_resolves_its_repository_tag():
    class RecordingAPI(MODULE.GitHubAPI):
        def __init__(self):
            super().__init__()
            self.paths = []

        def get(self, path):
            self.paths.append(path)
            return {"object": {"type": "commit", "sha": "a" * 40}}

    api = RecordingAPI()
    assert api.resolve_tag("github/codeql-action/upload-sarif", "v4") == "a" * 40
    assert api.paths == ["/repos/github/codeql-action/git/ref/tags/v4"]
