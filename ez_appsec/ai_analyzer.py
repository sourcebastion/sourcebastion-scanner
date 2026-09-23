"""Deprecated compatibility shim for the removed LLM scan integration."""

from pathlib import Path
from typing import Any, Dict, List, Optional

from ez_appsec.config import Config


class AIAnalyzer:
    """Return scanner findings unchanged without contacting an LLM provider.

    The class remains importable for compatibility with integrations built before
    SourceBastion Scan made its scan boundary deterministic. New code should use
    scanner-native remediation metadata instead.
    """

    def __init__(self, config: Config):
        self.config = config

    def analyze(
        self,
        issues: List[Dict[str, Any]],
        path: Path,
        custom_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return findings unchanged; legacy prompt arguments are ignored."""
        return {
            "enhanced_issues": issues,
            "message": "LLM scan enrichment is disabled; findings are unchanged.",
        }
