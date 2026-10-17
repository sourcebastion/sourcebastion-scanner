"""Vendored-set changes must stop a reviewed dependency closure update."""
import hashlib
import importlib.util
import json
from pathlib import Path
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_artifacts', ROOT / 'scripts/scanner_artifacts.py')
artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)
TARGET = 'musllinux_1_2_aarch64'


def wheel(root, name='sample', library=b'\x7fELForiginal', member='sample.libs/libsample.so.1'):
    path = root / (name + '-1.0-py3-none-any.whl')
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr(name + '-1.0.dist-info/METADATA', 'Name: ' + name + '\nVersion: 1.0\n')
        archive.writestr('sample/extension.cpython-314-aarch64-linux-musl.so', b'\x7fELFextension')
        if library is not None:
            archive.writestr(member, library)
    return path


@pytest.fixture
def baseline(tmp_path, monkeypatch):
    wheels = tmp_path / 'wheels'
    wheels.mkdir()
    wheel(wheels)
    rows = artifacts.bundled_natives(wheels)
    path = tmp_path / 'manifest.json'
    path.write_text(json.dumps({'schema_version': 1, 'targets': {
        TARGET: rows, 'musllinux_1_2_x86_64': []}}))
    monkeypatch.setattr(artifacts, 'NATIVES', path)
    return wheels


def test_manifest_binds_owner_wheel_and_library_bytes(baseline):
    rows = artifacts.verify_bundled_natives(baseline, TARGET)
    assert len(rows) == 1
    assert rows[0]['distribution'] == 'sample'
    assert rows[0]['version'] == '1.0'
    assert rows[0]['bytes'] == len(b'\x7fELForiginal')
    assert rows[0]['sha256'] == hashlib.sha256(b'\x7fELForiginal').hexdigest()
    assert rows[0]['wheel_sha256'] == hashlib.sha256(next(baseline.glob('*.whl')).read_bytes()).hexdigest()


@pytest.mark.parametrize('change', ['add', 'remove', 'same-size-bytes', 'new-owner', 'renamed-path'])
def test_changed_vendored_set_refuses(baseline, change):
    if change == 'add':
        with zipfile.ZipFile(next(baseline.glob('*.whl')), 'a') as archive:
            archive.writestr('sample.libs/libextra.so.2', b'\x7fELFextra')
    elif change == 'remove':
        wheel(baseline, library=None)
    elif change == 'same-size-bytes':
        wheel(baseline, library=b'\x7fELFtampered')
    elif change == 'new-owner':
        wheel(baseline, name='previously-unseen-package', member='unexpected/libnew.so.1')
    else:
        wheel(baseline, member='elsewhere/libsample.so.1')
    with pytest.raises(ValueError, match='bundled native library drift'):
        artifacts.verify_bundled_natives(baseline, TARGET)


def test_wrong_architecture_cannot_reuse_another_manifest_entry(baseline):
    with pytest.raises(ValueError, match='library drift'):
        artifacts.verify_bundled_natives(baseline, 'musllinux_1_2_x86_64')


def test_semgrep_wheel_data_layout_is_included(tmp_path):
    wheel(tmp_path, name='semgrep', member='semgrep-1.0.data/purelib/semgrep/bin/libs/unusual.so.1')
    assert len(artifacts.bundled_natives(tmp_path)) == 1


def test_malformed_or_duplicate_native_members_refuse(tmp_path):
    path = wheel(tmp_path, library=b'not an ELF')
    with pytest.raises(ValueError, match='not ELF'):
        artifacts.bundled_natives(tmp_path)
    wheel(tmp_path)
    with zipfile.ZipFile(path, 'a') as archive:
        with pytest.warns(UserWarning, match='Duplicate name'):
            archive.writestr('sample.libs/libsample.so.1', b'\x7fELFchanged')
    with pytest.raises(ValueError, match='duplicate wheel member'):
        artifacts.bundled_natives(tmp_path)


def test_missing_architecture_manifest_refuses(baseline):
    artifacts.NATIVES.write_text(json.dumps({'schema_version': 1, 'targets': {TARGET: []}}))
    with pytest.raises(ValueError, match='manifest targets'):
        artifacts.verify_bundled_natives(baseline, TARGET)


def test_existing_dependency_verification_stops_on_new_vendor(baseline, monkeypatch):
    monkeypatch.setattr(artifacts, 'GROUPS', ('semgrep',))
    monkeypatch.setattr(artifacts, 'TARGETS', (TARGET, 'musllinux_1_2_x86_64'))
    monkeypatch.setattr(artifacts, 'validate_dependencies', lambda *args: None)
    monkeypatch.setattr(artifacts, 'verify_closure', lambda *args: None)

    def download(command, **kwargs):
        destination = Path(command[command.index('--dest') + 1])
        wheel(destination, name='new-vendor', member='new-vendor.libs/libnew.so.1')

    monkeypatch.setattr(artifacts.subprocess, 'run', download)
    with pytest.raises(ValueError, match='bundled native library drift'):
        artifacts.verify_dependencies(baseline, {})
