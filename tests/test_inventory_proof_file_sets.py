"""Pure source/installed identity checks; no image or scanner is executed."""

import hashlib
from pathlib import Path
import runpy
import sys
from types import ModuleType, SimpleNamespace

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def write(root, name, raw=b"finite source bytes"):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return path


def verifier(name, work):
    helper = runpy.run_path(str(SCRIPTS / name), run_name="pure_file_set_tests")
    helper["inventory_bindings"].__globals__["WORK"] = work
    return helper


@pytest.fixture(params=["verify-inventory-dependency-job.py", "verify-inventory-entrypoint.py"])
def module_case(request, tmp_path):
    work, installed = tmp_path / "checkout", tmp_path / "installed"
    source = work / "sourcebastion/inventory"
    names = ["contract.py", "helper.js", "helper.cjs", "helper.mjs", "vendor/data.json"]
    for name in names:
        write(source, name)
        write(installed, name)
    return verifier(request.param, work)["inventory_bindings"], source, installed, names


def test_matching_new_modules_do_not_require_a_count_update(module_case):
    verify, source, installed, names = module_case
    new = "future/another_helper.py"
    write(source, new, b"new source bytes")
    write(installed, new, b"new source bytes")
    expected = {name: hashlib.sha256(b"finite source bytes").hexdigest() for name in names}
    expected[new] = hashlib.sha256(b"new source bytes").hexdigest()
    assert verify(installed) == expected


@pytest.mark.parametrize("drift", ["missing", "extra", "changed", "renamed"])
def test_module_identity_refuses_missing_extra_changed_and_equal_count_renames(module_case, drift):
    verify, source, installed, _ = module_case
    if drift == "missing":
        (installed / "contract.py").unlink()
    elif drift == "extra":
        write(installed, "unexpected.py")
    elif drift == "changed":
        write(installed, "contract.py", b"changed installed bytes")
    else:
        (installed / "contract.py").rename(installed / "renamed.py")
    with pytest.raises(AssertionError):
        verify(installed)


@pytest.mark.parametrize("existing", [False, True])
def test_empty_or_missing_module_roots_are_refused(module_case, existing):
    verify, source, installed, names = module_case
    for root in (source, installed):
        for path in sorted(root.rglob("*"), reverse=True):
            if path.is_file():
                path.unlink()
            else:
                path.rmdir()
        if not existing:
            root.rmdir()
    with pytest.raises(AssertionError):
        verify(installed)


def payload_case(tmp_path, monkeypatch, drift=None):
    work, package = tmp_path / "checkout", tmp_path / "site/sourcebastion"
    files = {
        "inventory_entrypoint.py": b"entrypoint source",
        "inventory/contract.py": b"canonical source",
        "inventory/future_helper.py": b"new helper",
        "templates/example.txt": b"template source",
    }
    for name, raw in files.items():
        write(work / "sourcebastion", name, raw)
        write(package, name, raw)
    records = [Path("sourcebastion") / name for name in files]
    if drift == "missing":
        records.remove(Path("sourcebastion/templates/example.txt"))
    elif drift == "extra":
        write(package, "unrecorded.txt")
        write(work / "sourcebastion", "unrecorded.txt")
        records.append(Path("sourcebastion/unrecorded.txt"))
    elif drift == "changed":
        write(package, "templates/example.txt", b"changed template")
    elif drift == "duplicate":
        records.append(records[0])
    elif drift == "oversized-record-list":
        for i in range(512):
            name = f"templates/cap-{i}.txt"
            write(work / "sourcebastion", name)
            write(package, name)
            records.append(Path("sourcebastion") / name)
    distribution = SimpleNamespace(files=records, version="proof", locate_file=lambda row: package.parent / row)
    helper = verifier("verify-inventory-entrypoint.py", work)
    monkeypatch.setattr(helper["metadata"], "distribution", lambda name: distribution)
    product = ModuleType("sourcebastion")
    product.inventory_entrypoint = SimpleNamespace(__file__=str(package / "inventory_entrypoint.py"))
    inventory = ModuleType("sourcebastion.inventory")
    inventory.contract = SimpleNamespace(__file__=str(package / "inventory/contract.py"))
    monkeypatch.setitem(sys.modules, "sourcebastion", product)
    monkeypatch.setitem(sys.modules, "sourcebastion.inventory", inventory)
    return helper["installed_bindings"], {"sourcebastion/" + name for name in files}


def test_distribution_payload_set_accepts_new_exact_source_files(tmp_path, monkeypatch):
    verify, expected = payload_case(tmp_path, monkeypatch)
    assert set(verify()["package_payloads"]) == expected


@pytest.mark.parametrize("drift", ["missing", "extra", "changed", "duplicate", "oversized-record-list"])
def test_distribution_still_refuses_payload_drift_and_retains_record_cap(tmp_path, monkeypatch, drift):
    verify, _ = payload_case(tmp_path, monkeypatch, drift)
    with pytest.raises(AssertionError):
        verify()
