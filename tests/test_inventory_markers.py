"""Marker decisions never borrow scanner-host or implicit optional activation."""

import packaging.markers
import pytest

from sourcebastion.inventory.contract import Environment
from sourcebastion.inventory.inputs import InputRefusal
from sourcebastion.inventory.markers import context_key, disjoint, marker_activation


@pytest.fixture(autouse=True)
def forbid_host_marker_environment(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("marker evaluation accessed host defaults")

    monkeypatch.setattr(packaging.markers, "default_environment", forbidden)
    monkeypatch.setattr(packaging.markers.Marker, "evaluate", forbidden)


@pytest.mark.parametrize(
    "expression",
    [
        'python_version < "3.13"',
        'sys_platform == "linux"',
        '"3.14" > python_version',
        'extra == "test"',
        '"test" in extras',
        '"dev" in dependency_groups',
    ],
)
def test_unspecified_target_variables_are_unknown(expression):
    decision = marker_activation(expression, Environment())
    assert decision.activation == "unknown" and decision.reason == "missing-marker-input"


@pytest.mark.parametrize(
    "expression,expected",
    [
        ('python_version < "3.13"', "active"),
        ('python_full_version == "3.12.9"', "active"),
        ('"3.14" > python_version', "active"),
        ('python_version >= "3.13"', "inactive"),
        ('sys_platform == "win32"', "inactive"),
        ('sys_platform in "linux,darwin"', "active"),
        ('(python_version < "3.13" and sys_platform == "linux") or python_version == "3.14"', "active"),
    ],
)
def test_only_explicit_target_inputs_are_evaluated(expression, expected):
    target = Environment(policy="explicit-target", python_version="3.12.9", platform="linux")
    assert marker_activation(expression, target).activation == expected


def test_minor_target_does_not_supply_missing_full_version_or_other_variables():
    target = Environment(policy="explicit-target", python_version="3.12")
    assert marker_activation('python_full_version < "3.12.9"', target).activation == "unknown"
    assert marker_activation('python_version == "3.12" or sys_platform == "linux"', target).activation == "unknown"
    assert marker_activation(None, Environment()).activation == "active"


@pytest.mark.parametrize(
    "expression",
    [
        "python_version ==",
        'python_version == "3.12"\n',
        "(" * 33 + 'python_version == "3.12"' + ")" * 33,
        'python_version == "' + "1" * 129 + '"',
        "x" * 16385,
    ],
)
def test_invalid_or_excessive_markers_refuse_without_raw_expression(expression):
    decision = marker_activation(expression, Environment())
    assert decision.activation == "unknown"
    assert decision.reason.startswith(("invalid-marker", "marker-complexity"))
    assert expression not in repr(decision)


def test_missing_or_invalid_comparison_is_not_inactive():
    target = Environment(policy="explicit-target", marker_inputs=(("os_name", "posix"),))
    decision = marker_activation('os_name ~= "posix"', target)
    assert decision.activation == "unknown" and decision.reason == "unsupported-marker-comparison"


@pytest.mark.parametrize("os_name,sys_platform", [("posix", "posix"), ("sys_platform", "linux")])
def test_variable_to_variable_comparison_is_not_misread_as_a_literal(os_name, sys_platform):
    target = Environment(policy="explicit-target", marker_inputs=(("os_name", os_name), ("sys_platform", sys_platform)))
    decision = marker_activation("os_name == sys_platform", target)
    assert decision.activation == "unknown" and decision.reason == "unsupported-marker-comparison"


def test_controller_epoch_or_budget_refusal_propagates():
    def refused():
        raise InputRefusal("changed-input-bytes")

    with pytest.raises(InputRefusal, match="changed-input-bytes"):
        marker_activation('python_version == "3.12"', Environment(), check=refused)


def test_flat_conjunction_order_is_equivalent_but_reversed_predicates_are_opaque():
    a = 'python_version >= "3.12" and sys_platform == "linux"'
    b = 'sys_platform == "linux" and python_version >= "3.12"'
    assert context_key(a) == context_key(b)
    assert context_key('"3.12" <= python_version')[0] == "opaque"
    assert context_key('python_version >= "3.12" or sys_platform == "linux"')[0] == "opaque"


@pytest.mark.parametrize(
    "left,right,expected",
    [
        ('python_version < "3.13"', 'python_version >= "3.13"', True),
        ('python_full_version <= "3.13.9"', 'python_full_version > "3.13.9"', True),
        ('sys_platform == "linux"', 'sys_platform != "linux"', True),
        ('sys_platform < "linux"', 'sys_platform >= "linux"', False),
        ('python_version < "3.13"', 'python_version >= "3.12"', False),
        ('python_version < "3.13" or sys_platform == "linux"', 'python_version >= "3.13"', False),
    ],
)
def test_disjointness_is_a_narrow_complement_proof(left, right, expected):
    assert disjoint(left, right) is expected
