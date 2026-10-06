"""Conservative marker equivalence/disjointness; never select host environment.

This experiment uses the pinned packaging 25.0 marker tree for a narrow proof:
flat conjunction ordering and exact complementary predicates. All other shapes
remain unproved, rather than borrowing the scanner host's target environment.
"""

from packaging.markers import Marker


def conjunction(marker):
    if marker is None:
        return ()
    tree = Marker(marker)._markers
    if not isinstance(tree, list) or not tree or len(tree) > 257:
        return None
    atoms = []
    for index, item in enumerate(tree):
        if index % 2:
            if item != "and":
                return None
        elif isinstance(item, tuple) and len(item) == 3:
            left, operator, right = item
            # A reversed comparison has different version/string semantics;
            # refuse to normalize it merely by swapping its operands.
            if type(left).__name__ != "Variable" or type(right).__name__ != "Value":
                return None
            if not all(isinstance(value.value, str) for value in item):
                return None
            atoms.append((left.value, operator.value, right.value))
        else:
            return None
    return tuple(sorted(set(atoms)))


def context_key(marker):
    atoms = conjunction(marker)
    return ("conjunction", atoms) if atoms is not None else ("literal", marker)


def disjoint(left, right):
    """Prove only exact ==/!= complements, which share marker semantics.

    Ordered version comparisons have PEP 440 prerelease subtleties, so the
    familiar < / >= pair is proved only for known numeric Python version
    variables with matching plain release literals. No environment is guessed.
    """
    a, b = conjunction(left), conjunction(right)
    if a is None or b is None:
        return False
    complements = {("==", "!="), ("!=", "==")}
    for variable, operator, value in a:
        for other_variable, other_operator, other_value in b:
            if variable != other_variable or value != other_value:
                continue
            if (operator, other_operator) in complements:
                return True
            if variable in {"python_version", "python_full_version"} and all(
                component.isascii() and component.isdigit() for component in value.split(".")
            ):
                if (operator, other_operator) in {("<", ">="), (">=", "<"), ("<=", ">"), (">", "<=")}:
                    return True
    return False
