"""Regression tests for the retired scanner-side LLM agent."""

import builtins
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from ez_appsec.agent import (
    AgentResult,
    LLM_AGENT_REMOVED_MESSAGE,
    SecurityAgent,
)
from ez_appsec.cli import main


def test_legacy_agent_result_remains_importable():
    result = AgentResult(summary="legacy")

    assert result.summary == "legacy"
    assert result.findings == []


@pytest.mark.parametrize("method,args", [("run", ("scan .",)), ("scan_and_triage", (".",))])
def test_legacy_agent_never_imports_a_provider(method, args):
    real_import = builtins.__import__

    def reject_provider_import(name, *import_args, **import_kwargs):
        if name.split(".", 1)[0] in {"anthropic", "openai"}:
            raise AssertionError(f"legacy agent imported provider: {name}")
        return real_import(name, *import_args, **import_kwargs)

    agent = SecurityAgent()
    with patch("builtins.__import__", side_effect=reject_provider_import):
        with pytest.raises(RuntimeError, match="SourceBastion Ops"):
            getattr(agent, method)(*args)


def test_legacy_agent_rejects_tool_registration():
    with pytest.raises(RuntimeError, match="SourceBastion Ops"):
        SecurityAgent().register_tool("scan", lambda: None, {})


def test_agent_cli_directs_users_to_ops(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "must-not-be-used")

    result = CliRunner().invoke(main, ["agent", "scan ."])

    assert result.exit_code != 0
    assert LLM_AGENT_REMOVED_MESSAGE in result.output
    assert "API key" not in result.output
