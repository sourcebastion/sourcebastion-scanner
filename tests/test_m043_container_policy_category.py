"""M043: a policy rule must be able to name container findings.

Container findings join the complete snapshot that the gate evaluates, so
`an image-only violating finding can fail the gate` is only true if a rule can
say which findings it means. It could not: the image scanner labels its
findings `container_scanning`, the hosted gate and Cedar v2 call the category
`container_images`, and `PolicyRule` accepted neither -- both were rejected as
invalid categories. An image-only violation could therefore only be caught by
a severity-only rule, which also catches everything else.
"""

import pytest

from sourcebastion.policy import (
    CONTAINER_CATEGORY,
    PolicyEngine,
    PolicyRule,
    canonical_category,
)


def _image_finding(severity="critical", category="container_scanning"):
    return {
        "severity": severity,
        "category": category,
        "title": "vulnerable package in base image",
        "rule_id": "CVE-2026-0001",
        "scanner": "grype",
    }


@pytest.mark.parametrize(
    "written",
    ["container_images", "container_scanning", "container-scanning", "container", "image"],
)
def test_a_rule_may_name_containers_in_any_spelling(written):
    """A policy author should not have to know which component made the label."""
    rule = PolicyRule(name="r", category=written, severity="critical", action="fail")
    assert rule.category == CONTAINER_CATEGORY


def test_an_unknown_category_is_still_rejected():
    """Canonicalising must not become a way to accept anything."""
    with pytest.raises(ValueError):
        PolicyRule(name="r", category="not-a-category", action="fail")


def test_an_image_only_violation_fails_the_gate():
    """The acceptance criterion from the issue, asserted end to end."""
    engine = PolicyEngine(
        [
            PolicyRule(
                name="no-critical-container",
                category="container_images",
                severity="critical",
                action="fail",
                max_count=0,
            )
        ]
    )
    result = engine.evaluate([_image_finding()])
    assert result["failed"] is True
    assert len(result["violations"]) == 1


def test_a_rule_written_in_the_gate_vocabulary_matches_the_scanner_label():
    """`container_images` in the rule must match `container_scanning` findings.

    This is the mismatch that made the category useless even once allowed:
    the matcher compared raw strings, so the two vocabularies never met.
    """
    rule = PolicyRule(
        name="r", category="container_images", severity="critical", action="fail"
    )
    assert rule.matching_findings([_image_finding()])


def test_container_rules_do_not_match_other_findings():
    """A category filter must still exclude."""
    rule = PolicyRule(
        name="r", category="container_images", severity="critical", action="fail"
    )
    code_finding = {"severity": "critical", "category": "sast", "title": "eval"}
    assert rule.matching_findings([code_finding]) == []


def test_other_categories_are_unchanged():
    """The fold is narrow on purpose; it must not rewrite anything else."""
    for value in ("sast", "secrets", "iac", "cve", "dependency_scanning"):
        assert canonical_category(value) == value
        assert PolicyRule(name="r", category=value, action="fail").category == value


def test_canonical_category_passes_through_unknown_values():
    """Validation rejects unknown categories; the helper does not invent one."""
    assert canonical_category("something-else") == "something-else"
    assert canonical_category(None) is None
