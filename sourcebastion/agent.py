"""Compatibility surface for the retired scanner-side LLM agent.

LLM-assisted maintenance belongs to SourceBastion Ops. The scanner package
must never send source code or findings to a model provider.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


MAX_TASK_LENGTH = 4096
LLM_AGENT_REMOVED_MESSAGE = (
    "The scanner-side LLM agent has been removed. Use the separately operated "
    "SourceBastion Ops agent for LLM-assisted maintenance."
)


@dataclass
class AgentResult:
    """Legacy result type retained for import compatibility."""

    findings: List[Dict[str, Any]] = field(default_factory=list)
    actions_taken: List[str] = field(default_factory=list)
    summary: str = ""
    raw_messages: List[Any] = field(default_factory=list)


class SecurityAgent:
    """Disabled compatibility shim for the former scanner-side LLM agent."""

    def __init__(
        self,
        model: Optional[str] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
        allowed_root: Optional[str] = None,
    ):
        self.model = model
        self.tools = tools
        self.allowed_root = allowed_root

    def register_tool(self, *args: Any, **kwargs: Any) -> None:
        """Reject tool registration because scanner-side agents are disabled."""
        raise RuntimeError(LLM_AGENT_REMOVED_MESSAGE)

    def run(
        self, task: str, context: Optional[Dict[str, Any]] = None
    ) -> AgentResult:
        """Reject execution without importing a provider or reading credentials."""
        raise RuntimeError(LLM_AGENT_REMOVED_MESSAGE)

    def scan_and_triage(self, path: str) -> AgentResult:
        """Reject the legacy scan-and-triage workflow."""
        raise RuntimeError(LLM_AGENT_REMOVED_MESSAGE)
