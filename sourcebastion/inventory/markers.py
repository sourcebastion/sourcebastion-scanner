"""Bounded PEP508 marker semantics using only explicitly recorded inputs.

packaging 26.3 is pinned and hash-verified by the runtime locks. Its public
Marker.evaluate fills unspecified values from the host. The narrow private
tree evaluator used here receives only the admitted target dictionary; tests
bind its behavior and forbid calls to either host-default/public evaluator.
Optional extras/groups require separately evidenced activation and stay unknown
here. A marker decision alone does not activate an optional dependency group.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

from packaging.markers import Marker, UndefinedComparison, UndefinedEnvironmentName, Variable, _evaluate_markers

from .contract import Environment
from .inputs import InputRefusal
from .requirements import MAX_LOGICAL_LINE, MAX_NESTING, MAX_NUMERIC_RUN, outside_quotes

VERSION = "sourcebastion.python-markers/1"
MAX_TREE_NODES = 1024


@dataclass(frozen=True)
class MarkerDecision:
    activation: str
    reason: str
    variables: tuple


def _tree(expression, check):
    if not isinstance(expression, str) or not expression or len(expression) > MAX_LOGICAL_LINE:
        raise InputRefusal("invalid-marker-size")
    if any(ord(char) < 32 or 127 <= ord(char) < 160 for char in expression):
        raise InputRefusal("invalid-marker-control")
    if re.search(r"\d{" + str(MAX_NUMERIC_RUN + 1) + r",}", expression):
        raise InputRefusal("marker-complexity-budget-exceeded")
    depth, lexical = 0, []
    for _index, char in outside_quotes(expression):
        check()
        lexical.append(char)
        if char == "(":
            depth += 1
            if depth > MAX_NESTING:
                raise InputRefusal("marker-complexity-budget-exceeded")
        elif char == ")":
            depth -= 1
    if len(re.findall(r"\b(?:and|or)\b", "".join(lexical))) > 128:
        raise InputRefusal("marker-complexity-budget-exceeded")
    try:
        tree = Marker(expression)._markers
    except (ValueError, RecursionError):
        raise InputRefusal("invalid-marker") from None
    variables, stack, nodes = set(), [iter(tree)], 0
    while stack:
        check()
        try:
            node = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        nodes += 1
        if nodes > MAX_TREE_NODES or len(stack) > MAX_NESTING + 1:
            raise InputRefusal("marker-complexity-budget-exceeded")
        if isinstance(node, list):
            stack.append(iter(node))
        elif isinstance(node, tuple) and len(node) == 3:
            left, _operator, right = node
            if isinstance(left, Variable) == isinstance(right, Variable):
                raise InputRefusal("unsupported-marker-comparison")
            for value in (left, right):
                if isinstance(value, Variable):
                    variables.add(value.value)
        elif node not in {"and", "or"}:
            raise InputRefusal("unsupported-marker-tree")
    return tree, tuple(sorted(variables))


def marker_activation(expression, environment, *, check=lambda: None):
    """Return active/inactive only when every used target variable is recorded.

    Missing variables remain unknown even if a partial boolean expression could
    short circuit. Stable refusals contain no customer marker text. Controller
    budget/epoch refusals from check() propagate instead of becoming decisions.
    """
    if not isinstance(environment, Environment):
        raise TypeError("validated Environment required")
    environment = Environment.model_validate(environment)
    check()
    if expression is None:
        return MarkerDecision("active", "unconditional-marker", ())
    try:
        tree, variables = _tree(expression, check)
    except InputRefusal as refusal:
        if refusal.reason.startswith(("invalid-marker", "unsupported-marker", "marker-complexity")):
            return MarkerDecision("unknown", refusal.reason, ())
        raise
    target = environment.marker_environment
    if any(variable not in target for variable in variables):
        return MarkerDecision("unknown", "missing-marker-input", variables)
    check()
    try:
        selected = _evaluate_markers(tree, target)
    except (UndefinedComparison, UndefinedEnvironmentName, ValueError, RecursionError):
        return MarkerDecision("unknown", "unsupported-marker-comparison", variables)
    return MarkerDecision("active" if selected else "inactive", "explicit-marker-inputs", variables)


def conjunction(expression, *, check=lambda: None):
    """Narrow equivalence proof: flat AND, variable on left, scalar on right.

    Other valid marker trees remain opaque. Reversing comparisons changes
    version/string semantics and is deliberately not normalized here.
    """
    if expression is None:
        return ()
    try:
        tree, _variables = _tree(expression, check)
    except InputRefusal as refusal:
        if refusal.reason.startswith(("invalid-marker", "unsupported-marker", "marker-complexity")):
            return None
        raise
    atoms = []
    for index, node in enumerate(tree):
        check()
        if index % 2:
            if node != "and":
                return None
        elif isinstance(node, tuple) and len(node) == 3:
            left, operator, right = node
            if not isinstance(left, Variable) or type(right).__name__ != "Value":
                return None
            atoms.append((left.value, operator.value, right.value))
        else:
            return None
    return tuple(sorted(atoms))


def context_key(expression, *, check=lambda: None):
    atoms = conjunction(expression, check=check)
    return ("conjunction", atoms) if atoms is not None else ("opaque", expression)


def disjoint(left, right, *, check=lambda: None):
    """Prove only exact complementary predicates, never infer host activation."""
    a, b = conjunction(left, check=check), conjunction(right, check=check)
    if a is None or b is None:
        return False
    for variable, operator, value in a:
        for other_variable, other_operator, other_value in b:
            check()
            if variable != other_variable or value != other_value:
                continue
            if (operator, other_operator) in {("==", "!="), ("!=", "==")}:
                return True
            if variable in {"python_version", "python_full_version"} and all(
                component.isascii() and component.isdigit() for component in value.split(".")
            ):
                if (operator, other_operator) in {("<", ">="), (">=", "<"), ("<=", ">"), (">", "<=")}:
                    return True
    return False
