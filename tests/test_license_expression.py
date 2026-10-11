"""M048 S02: SPDX expressions evaluated per term, never as raw strings."""

import pytest

from sourcebastion.license_expression import (
    CANONICAL,
    DENIED,
    DEPRECATED,
    LICENSEREF,
    PERMITTED,
    SPDX_LICENSE_LIST_VERSION,
    UNDETERMINED,
    UNPARSED,
    Compound,
    LicensePolicy,
    PolicyError,
    Term,
    evaluate,
    parse_license,
    within_expression_budget,
)


def result(raw, allowed=(), denied=()):
    return evaluate(raw, LicensePolicy(allowed=allowed, denied=denied)).result


class TestRecordedDefects:
    """The four defects reproduced on main 7052913, with corrected outcomes."""

    def test_conjunctive_denied_term_does_not_escape(self):
        assert result("MIT AND GPL-3.0-only", denied=["GPL*"]) == DENIED

    def test_deny_only_noassertion_is_not_permitted(self):
        assert result("NOASSERTION", denied=["AGPL*"]) == UNDETERMINED

    def test_disjunction_with_allowed_branch_is_permitted(self):
        evaluation = evaluate("MIT OR GPL-3.0-only", LicensePolicy(allowed=["MIT"]))
        assert evaluation.result == PERMITTED
        assert evaluation.satisfied_by == (Term("MIT"),)

    def test_free_text_is_unparsed_not_matched(self):
        evaluation = evaluate("Foo", LicensePolicy(allowed=["Foo"]))
        assert evaluation.value.parse == UNPARSED
        assert evaluation.result == UNDETERMINED


class TestParse:
    def test_canonicalizes_case(self):
        value = parse_license("mit or apache-2.0")
        assert value.expression == "MIT OR Apache-2.0"
        assert value.parse == CANONICAL

    def test_nesting_and_precedence(self):
        value = parse_license("MIT AND Apache-2.0 OR BSD-3-Clause")
        assert value.tree == Compound(
            "OR",
            (Compound("AND", (Term("MIT"), Term("Apache-2.0"))), Term("BSD-3-Clause")),
        )

    def test_parentheses(self):
        value = parse_license("MIT AND (Apache-2.0 OR BSD-3-Clause)")
        assert value.tree == Compound(
            "AND",
            (Term("MIT"), Compound("OR", (Term("Apache-2.0"), Term("BSD-3-Clause")))),
        )

    def test_with_is_one_term(self):
        value = parse_license("gpl-2.0-or-later with classpath-exception-2.0")
        assert value.tree == Term("GPL-2.0-or-later", "Classpath-exception-2.0")

    def test_deprecated_is_reported_not_rewritten(self):
        value = parse_license("GPL-2.0+")
        assert value.parse == DEPRECATED
        assert value.expression == "GPL-2.0+"

    def test_licenseref(self):
        assert parse_license("LicenseRef-Internal").parse == LICENSEREF

    @pytest.mark.parametrize(
        "raw", ["NOASSERTION", "NONE", "", "   ", "see LICENSE", "BSD-like", "GPL-2.0-only WITH Foo"]
    )
    def test_unparsed_kept_verbatim(self, raw):
        value = parse_license(raw)
        assert value.parse == UNPARSED
        assert value.expression is None
        assert value.raw == raw

    def test_over_budget_is_unparsed_without_parsing(self):
        raw = "(" * 33 + "MIT" + ")" * 33
        assert not within_expression_budget(raw)
        assert parse_license(raw).parse == UNPARSED

    def test_pinned_list_version_is_exposed(self):
        assert SPDX_LICENSE_LIST_VERSION == "3.27.0"


class TestDisjunction:
    def test_denied_only_when_every_branch_denied(self):
        assert result("GPL-3.0-only OR AGPL-3.0-only", denied=["GPL-*", "AGPL-*"]) == DENIED

    def test_one_permitted_branch_suffices_under_deny_only(self):
        assert result("MIT OR GPL-3.0-only", denied=["GPL-*"]) == PERMITTED

    def test_mixed_denied_and_undetermined_is_undetermined(self):
        assert result("GPL-3.0-only OR LicenseRef-X", denied=["GPL-*"]) == UNDETERMINED

    def test_satisfying_branch_is_the_whole_conjunction(self):
        evaluation = evaluate(
            "(MIT AND ISC) OR GPL-3.0-only", LicensePolicy(allowed=["MIT", "ISC"])
        )
        assert evaluation.satisfied_by == (Term("MIT"), Term("ISC"))


class TestConjunction:
    def test_every_term_must_be_permitted(self):
        assert result("MIT AND Apache-2.0", allowed=["MIT"]) == UNDETERMINED
        assert result("MIT AND Apache-2.0", allowed=["MIT", "Apache-2.0"]) == PERMITTED

    def test_any_denied_term_denies(self):
        evaluation = evaluate(
            "MIT AND (GPL-3.0-only OR AGPL-3.0-only)",
            LicensePolicy(allowed=["MIT"], denied=["GPL-*", "AGPL-*"]),
        )
        assert evaluation.result == DENIED
        assert set(evaluation.denied_terms) == {Term("GPL-3.0-only"), Term("AGPL-3.0-only")}


class TestExceptions:
    def test_allowing_base_allows_any_exception(self):
        assert result("Apache-2.0 WITH LLVM-exception", allowed=["Apache-2.0"]) == PERMITTED

    def test_exception_does_not_lift_a_denial(self):
        raw = "GPL-2.0-or-later WITH Classpath-exception-2.0"
        assert result(raw, denied=["GPL-*"]) == DENIED

    def test_exact_pair_lifts_a_denial(self):
        raw = "GPL-2.0-or-later WITH Classpath-exception-2.0"
        assert result(
            raw,
            allowed=["GPL-2.0-or-later WITH Classpath-exception-2.0"],
            denied=["GPL-*"],
        ) == PERMITTED

    def test_exact_pair_can_be_denied(self):
        raw = "GPL-2.0-or-later WITH Classpath-exception-2.0"
        assert result(raw, denied=["gpl-2.0-or-later with classpath-exception-2.0"]) == DENIED


class TestPolicyShapes:
    def test_wildcards_apply_to_identifiers(self):
        assert result("LGPL-2.1-only", denied=["GPL*"]) == PERMITTED
        assert result("LGPL-2.1-only", denied=["*GPL*"]) == DENIED

    def test_allow_list_leaves_unlisted_undetermined(self):
        assert result("ISC", allowed=["MIT"]) == UNDETERMINED

    def test_empty_policy_permits_spdx_but_not_unparsed(self):
        assert result("MIT") == PERMITTED
        assert result("UNKNOWN") == UNDETERMINED

    def test_licenseref_undetermined_unless_named_exactly(self):
        assert result("LicenseRef-Internal", denied=["GPL*"]) == UNDETERMINED
        assert result("LicenseRef-Internal", allowed=["LicenseRef-*"]) == UNDETERMINED
        assert result("LicenseRef-Internal", allowed=["LicenseRef-Internal"]) == PERMITTED
        assert result("LicenseRef-Internal", denied=["LicenseRef-Internal"]) == DENIED

    def test_denied_takes_priority_over_allowed(self):
        assert result("GPL-3.0-only", allowed=["GPL-3.0-only"], denied=["GPL-*"]) == DENIED

    @pytest.mark.parametrize(
        "entry", ["MIT OR Apache-2.0", "MIT and ISC", "(MIT)", "GPL-* WITH Classpath-exception-2.0", "", "  "]
    )
    def test_expression_entries_are_refused(self, entry):
        with pytest.raises(PolicyError):
            LicensePolicy(allowed=[entry])


class TestConfigValidation:
    def test_config_refuses_expression_entries(self):
        from pydantic import ValidationError

        from sourcebastion.config import LicensePolicyConfig

        with pytest.raises(ValidationError, match="list licenses, not expressions"):
            LicensePolicyConfig(denied_licenses=["GPL-3.0-only OR AGPL-3.0-only"])

    def test_config_accepts_identifiers_wildcards_and_pairs(self):
        from sourcebastion.config import LicensePolicyConfig

        config = LicensePolicyConfig(
            allowed_licenses=["MIT", "GPL-2.0-or-later WITH Classpath-exception-2.0"],
            denied_licenses=["GPL*", "LicenseRef-Proprietary"],
        )
        assert config.denied_licenses == ["GPL*", "LicenseRef-Proprietary"]
