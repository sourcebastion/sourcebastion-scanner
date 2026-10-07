"""Every runtime installation profile carries the declared runtime inputs."""

from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version
import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("group", ["runtime", "semgrep"])
@pytest.mark.parametrize(
    "target", ["manylinux_2_34_x86_64", "manylinux_2_34_aarch64", "musllinux_1_2_x86_64", "musllinux_1_2_aarch64"]
)
def test_every_target_runtime_installation_contains_compatible_direct_requirements(group, target):
    text = (ROOT / ".github/python-locks" / f"{group}-cp314-{target}.txt").read_text()
    pins = {}
    for line in text.replace("\\\n", " ").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        first = line.split()[0]
        if first == "semgrep":
            continue  # Its attested URL is checked by the artifact verifier.
        pin = Requirement(first)
        (specifier,) = pin.specifier
        assert specifier.operator == "=="
        pins[canonicalize_name(pin.name)] = Version(specifier.version)
    for line in (ROOT / "scripts/python-runtime.in").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        required = Requirement(line)
        name = canonicalize_name(required.name)
        assert name in pins, f"{group}/{target} missing runtime dependency {name}"
        assert pins[name] in required.specifier, f"{group}/{target} incompatible runtime dependency {name}"
