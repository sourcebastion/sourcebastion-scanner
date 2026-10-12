"""SPDX license expressions parsed and evaluated against a policy (M048 S02).

An expression is a grammar, not an identifier: ``MIT OR GPL-3.0-only`` offers a
choice and ``MIT AND GPL-3.0-only`` imposes both. Matching patterns against the
whole string, as the syft-era checker did, lets a conjunctive denied term escape
and treats free text as if it were an identifier. Here every value is first
canonicalized by the pinned ``packaging`` SPDX list, then evaluated per term.

Each evaluation has exactly one result: ``permitted``, ``denied`` or
``undetermined``. Undetermined is never permitted under any policy shape.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Iterable, Optional, Tuple, Union

from packaging.licenses import InvalidLicenseExpression, canonicalize_license_expression
from packaging.licenses._spdx import LICENSES, VERSION as _SPDX_LICENSE_LIST_VERSION

# The license-list version is a compatibility input (D4): changing it changes
# what a policy can recognise, exactly like an advisory snapshot.
SPDX_LICENSE_LIST_VERSION = _SPDX_LICENSE_LIST_VERSION

PERMITTED = "permitted"
DENIED = "denied"
UNDETERMINED = "undetermined"

CANONICAL = "canonical"
DEPRECATED = "deprecated"
LICENSEREF = "licenseref"
UNPARSED = "unparsed"

MAX_EXPRESSION_LENGTH = 16384
MAX_EXPRESSION_DEPTH = 32
MAX_EXPRESSION_OPERATORS = 128

_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")
_DEPRECATED_IDS = frozenset(v["id"] for v in LICENSES.values() if v["deprecated"])


class PolicyError(ValueError):
    """A license policy entry that cannot be matched against terms."""


def within_expression_budget(value: str) -> bool:
    """Whether *value* is small enough to hand to any expression parser.

    Shared with installed-metadata preflight so no parser, ours or a
    maintained one, receives an unbounded expression.
    """
    if re.search(r"\d{129,}", value):
        return False
    depth = 0
    for c in value:
        if c == "(":
            depth += 1
            if depth > MAX_EXPRESSION_DEPTH:
                return False
        elif c == ")":
            depth -= 1
    return len(re.findall(r"\b(?:and|or|AND|OR)\b", value)) <= MAX_EXPRESSION_OPERATORS


@dataclass(frozen=True)
class Term:
    """One license, optionally with an exception: ``X`` or ``X WITH E``."""

    license: str
    exception: Optional[str] = None

    def __str__(self) -> str:
        return f"{self.license} WITH {self.exception}" if self.exception else self.license

    @property
    def is_licenseref(self) -> bool:
        return self.license.startswith("LicenseRef-")


@dataclass(frozen=True)
class Compound:
    operator: str  # "AND" or "OR"
    operands: Tuple["Node", ...]


Node = Union[Term, Compound]


@dataclass(frozen=True)
class LicenseValue:
    """A raw license value and what the pinned SPDX list makes of it."""

    raw: str
    expression: Optional[str]
    parse: str
    tree: Optional[Node] = None


def parse_license(raw: str) -> LicenseValue:
    """Canonicalize *raw*; anything the SPDX list rejects stays ``unparsed``.

    Unparsed values are kept verbatim and are never guessed into identifiers.
    ``NOASSERTION`` and ``NONE`` are not license expressions and are unparsed.
    """
    text = raw.strip() if isinstance(raw, str) else ""
    if (
        not text
        or len(text) > MAX_EXPRESSION_LENGTH
        or not within_expression_budget(text)
    ):
        return LicenseValue(raw=raw, expression=None, parse=UNPARSED)
    try:
        expression = str(canonicalize_license_expression(text))
    except InvalidLicenseExpression:
        return LicenseValue(raw=raw, expression=None, parse=UNPARSED)
    tree = _Parser(expression).parse()
    terms = tuple(_terms(tree))
    if any(t.license.rstrip("+") in _DEPRECATED_IDS or t.license in _DEPRECATED_IDS for t in terms):
        kind = DEPRECATED
    elif any(t.is_licenseref for t in terms):
        kind = LICENSEREF
    else:
        kind = CANONICAL
    return LicenseValue(raw=raw, expression=expression, parse=kind, tree=tree)


class _Parser:
    """Recursive descent over a canonical expression: OR binds loosest."""

    def __init__(self, expression: str):
        self.tokens = _TOKEN.findall(expression)
        self.position = 0

    def parse(self) -> Node:
        node = self._or()
        if self.position != len(self.tokens):
            raise InvalidLicenseExpression(f"trailing tokens in {' '.join(self.tokens)!r}")
        return node

    def _peek(self) -> Optional[str]:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def _take(self) -> str:
        token = self._peek()
        if token is None:
            raise InvalidLicenseExpression("unexpected end of expression")
        self.position += 1
        return token

    def _or(self) -> Node:
        operands = [self._and()]
        while self._peek() == "OR":
            self._take()
            operands.append(self._and())
        return operands[0] if len(operands) == 1 else Compound("OR", tuple(operands))

    def _and(self) -> Node:
        operands = [self._term()]
        while self._peek() == "AND":
            self._take()
            operands.append(self._term())
        return operands[0] if len(operands) == 1 else Compound("AND", tuple(operands))

    def _term(self) -> Node:
        token = self._take()
        if token == "(":
            node = self._or()
            if self._take() != ")":
                raise InvalidLicenseExpression("unbalanced parentheses")
            return node
        if token in ("AND", "OR", "WITH", ")"):
            raise InvalidLicenseExpression(f"unexpected {token!r}")
        if self._peek() == "WITH":
            self._take()
            return Term(token, self._take())
        return Term(token)


def _terms(node: Node) -> Iterable[Term]:
    if isinstance(node, Term):
        yield node
    else:
        for operand in node.operands:
            yield from _terms(operand)


class LicensePolicy:
    """Allowed and denied lists matched per term, never per raw string.

    Entries are SPDX identifiers, identifier wildcards (``GPL-*``), exact
    ``X WITH E`` pairs or exact ``LicenseRef-*`` names. Entries containing
    ``AND``/``OR`` or parentheses are refused: a policy names licenses, not
    expressions.
    """

    def __init__(self, allowed: Iterable[str] = (), denied: Iterable[str] = ()):
        self.allowed = tuple(validate_policy_entry(e) for e in allowed)
        self.denied = tuple(validate_policy_entry(e) for e in denied)

    def evaluate_term(self, term: Term) -> str:
        pair = str(term)
        if term.exception and _names_exactly(self.allowed, pair):
            # Only an exact pair turns a denied license into a permitted one.
            return PERMITTED
        if term.is_licenseref:
            if _names_exactly(self.denied, pair) or _names_exactly(self.denied, term.license):
                return DENIED
            if _names_exactly(self.allowed, term.license):
                return PERMITTED
            return UNDETERMINED
        if _names_exactly(self.denied, pair) or _matches(self.denied, term.license):
            return DENIED
        if _matches(self.allowed, term.license):
            # Allowing X allows it under any exception: exceptions only grant.
            return PERMITTED
        return UNDETERMINED if self.allowed else PERMITTED


@dataclass(frozen=True)
class Evaluation:
    value: LicenseValue
    result: str
    # For a permitted choice, the terms of the branch that satisfies policy.
    satisfied_by: Tuple[Term, ...] = ()
    denied_terms: Tuple[Term, ...] = ()
    undetermined_terms: Tuple[Term, ...] = ()


def evaluate(raw: str, policy: LicensePolicy) -> Evaluation:
    """Evaluate one raw license value; unparsed values are undetermined."""
    value = parse_license(raw)
    if value.tree is None:
        return Evaluation(value=value, result=UNDETERMINED)
    result, satisfied = _evaluate(value.tree, policy)
    terms = tuple(_terms(value.tree))
    return Evaluation(
        value=value,
        result=result,
        satisfied_by=satisfied if result == PERMITTED else (),
        denied_terms=tuple(t for t in terms if policy.evaluate_term(t) == DENIED),
        undetermined_terms=tuple(t for t in terms if policy.evaluate_term(t) == UNDETERMINED),
    )


def _evaluate(node: Node, policy: LicensePolicy) -> Tuple[str, Tuple[Term, ...]]:
    if isinstance(node, Term):
        result = policy.evaluate_term(node)
        return result, (node,)
    outcomes = [_evaluate(operand, policy) for operand in node.operands]
    results = [r for r, _ in outcomes]
    if node.operator == "OR":
        for result, satisfied in outcomes:
            if result == PERMITTED:
                return PERMITTED, satisfied
        return (DENIED if all(r == DENIED for r in results) else UNDETERMINED), ()
    if DENIED in results:
        return DENIED, ()
    if all(r == PERMITTED for r in results):
        return PERMITTED, tuple(t for _, s in outcomes for t in s)
    return UNDETERMINED, ()


def validate_policy_entry(entry: str) -> str:
    """Normalize one allowed/denied entry, refusing expressions."""
    if not isinstance(entry, str) or not entry.strip():
        raise PolicyError("license policy entries must be non-empty strings")
    text = " ".join(entry.split())
    if "(" in text or ")" in text or {"AND", "OR"} & set(text.upper().split()):
        raise PolicyError(
            f"license policy entry {entry!r} is an expression; list licenses, not expressions"
        )
    words = text.split()
    cut = [i for i, w in enumerate(words) if w.upper() == "WITH"]
    parts = [" ".join(words)] if not cut else [" ".join(words[: cut[0]]), " ".join(words[cut[0] + 1 :])]
    if len(cut) > 1:
        parts.append("")
    if len(parts) > 2 or any(not p for p in parts):
        raise PolicyError(f"license policy entry {entry!r} is not a license or 'X WITH E' pair")
    if len(parts) == 2 and any(c in text for c in "*?["):
        raise PolicyError(f"license policy entry {entry!r}: 'X WITH E' pairs must be exact")
    return " WITH ".join(parts)


def _names_exactly(entries: Tuple[str, ...], name: str) -> bool:
    return any(e.upper() == name.upper() for e in entries)


def _matches(entries: Tuple[str, ...], identifier: str) -> bool:
    upper = identifier.upper()
    return any(
        " WITH " not in e.upper()
        and not e.upper().startswith("LICENSEREF-")
        and fnmatchcase(upper, e.upper())
        for e in entries
    )
