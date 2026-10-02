"""Policy engine for enforcing security standards on scan findings"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, field_validator


VALID_SEVERITIES = {"critical", "high", "medium", "low"}
#: The container category, canonically. The image scanner labels its findings
#: `container_scanning`; the hosted gate's vocabulary and Cedar v2 both call it
#: `container_images`. A rule may be written either way and matches either way:
#: which component produced the label is not something a policy author should
#: have to know.
CONTAINER_CATEGORY = "container_images"
_CONTAINER_ALIASES = frozenset(
    {
        "container_images",
        "container_scanning",
        "container-scanning",
        "container",
        "image",
    }
)
VALID_CATEGORIES = {
    "secrets",
    "sast",
    "iac",
    "cve",
    "dependency_scanning",
    # M043: container findings join the complete snapshot that the gate
    # evaluates, so a rule has to be able to name them. Without this, an
    # image-only violation could only be caught by a severity-only rule, and
    # `category: container_scanning` -- the value the findings actually carry
    # -- was rejected outright as invalid.
    CONTAINER_CATEGORY,
}


def canonical_category(value: str | None) -> str | None:
    """Fold the container spellings onto one name, leaving others untouched.

    Deliberately narrow. Normalising every category here would quietly change
    which findings existing rules match; container is the one vocabulary that
    is genuinely written several ways by components that must agree.
    """
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in _CONTAINER_ALIASES:
        return CONTAINER_CATEGORY
    return lowered
VALID_ACTIONS = {"fail", "warn", "ignore"}


class PolicyRule(BaseModel):
    """A single policy rule that evaluates scan findings"""

    severity: Optional[str] = None
    category: Optional[str] = None
    max_count: int = 0
    action: str = "fail"

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v):
        if v is not None and v not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{v}', must be one of: {', '.join(sorted(VALID_SEVERITIES))}"
            )
        return v

    @field_validator("category")
    @classmethod
    def validate_category(cls, v):
        if v is None:
            return v
        # Canonicalised rather than merely checked, so a rule written as
        # `container_scanning` is stored as the one name the matcher compares.
        canonical = canonical_category(v)
        if canonical not in VALID_CATEGORIES:
            raise ValueError(
                f"Invalid category '{v}', must be one of: {', '.join(sorted(VALID_CATEGORIES))}"
            )
        return canonical
        return v

    @field_validator("action")
    @classmethod
    def validate_action(cls, v):
        if v not in VALID_ACTIONS:
            raise ValueError(
                f"Invalid action '{v}', must be one of: {', '.join(sorted(VALID_ACTIONS))}"
            )
        return v

    def matching_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return findings that match this rule's severity and category filters."""
        matched = []
        for f in findings:
            if self.severity and f.get("severity", "").lower() != self.severity:
                continue
            if self.category:
                finding_cat = canonical_category(
                    f.get("category") or f.get("type") or f.get("scanner") or ""
                )
                if finding_cat != self.category:
                    continue
            matched.append(f)
        return matched

    def evaluate(self, findings: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Evaluate this rule against findings. Returns a violation dict or None."""
        matched = self.matching_findings(findings)
        count = len(matched)

        if count <= self.max_count:
            return None

        filters = []
        if self.severity:
            filters.append(f"severity={self.severity}")
        if self.category:
            filters.append(f"category={self.category}")
        filter_desc = " + ".join(filters) if filters else "all findings"

        return {
            "rule": {
                "severity": self.severity,
                "category": self.category,
                "max_count": self.max_count,
                "action": self.action,
            },
            "action": self.action,
            "count": count,
            "max_count": self.max_count,
            "description": f"{filter_desc}: {count} found, max allowed {self.max_count}",
        }


class PolicyEngine:
    """Evaluates a set of policy rules against scan findings"""

    def __init__(self, rules: List[PolicyRule]):
        self.rules = rules

    def evaluate(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate all policy rules against findings.

        Returns a dict with:
          - violations: list of violation dicts (action=fail or action=warn)
          - failed: bool — True if any 'fail' violation exists
          - summary: human-readable string
        """
        violations = []

        for rule in self.rules:
            if rule.action == "ignore":
                continue
            violation = rule.evaluate(findings)
            if violation is not None:
                violations.append(violation)

        failed = any(v["action"] == "fail" for v in violations)
        warnings = [v for v in violations if v["action"] == "warn"]
        failures = [v for v in violations if v["action"] == "fail"]

        parts = []
        if failures:
            parts.append(f"{len(failures)} failed")
        if warnings:
            parts.append(f"{len(warnings)} warning(s)")
        if not parts:
            parts.append("all policies passed")

        return {
            "violations": violations,
            "failed": failed,
            "summary": "Policy: " + ", ".join(parts),
        }
