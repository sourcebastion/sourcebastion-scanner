"""Vendored-set changes must stop a reviewed dependency closure update."""
import copy
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


def test_candidate_observation_does_not_authorize_new_vendor(baseline, monkeypatch, tmp_path):
    original = artifacts.NATIVES.read_bytes()
    monkeypatch.setattr(artifacts, 'GROUPS', ('semgrep',))
    monkeypatch.setattr(artifacts, 'TARGETS', (TARGET, 'musllinux_1_2_x86_64'))
    monkeypatch.setattr(artifacts, 'validate_dependencies', lambda *args: None)
    monkeypatch.setattr(artifacts, 'verify_closure', lambda *args: None)
    monkeypatch.setattr(artifacts, 'verify_native_notices', lambda *args: None)
    def download(command, **kwargs):
        destination = Path(command[command.index('--dest') + 1])
        wheel(destination, name='new-vendor', member='new-vendor.libs/libnew.so.1')
    monkeypatch.setattr(artifacts.subprocess, 'run', download)
    proposal = tmp_path / 'bundled-native-proposal.json'
    artifacts.verify_dependencies(baseline, {}, native_proposal=proposal)
    assert artifacts.NATIVES.read_bytes() == original
    observed = json.loads(proposal.read_text())['targets']
    assert set(observed) == set(artifacts.TARGETS)
    assert all(rows[0]['distribution'] == 'new-vendor' for rows in observed.values())
    with pytest.raises(ValueError, match='library drift'):
        artifacts.verify_dependencies(baseline, {})


def test_unchanged_native_candidate_does_not_create_a_spurious_pr(tmp_path):
    observed = json.loads(artifacts.NATIVES.read_text())['targets']
    proposal = tmp_path / 'bundled-native-proposal.json'
    proposal.write_text('stale proposal')
    artifacts.write_native_proposal(observed, proposal)
    assert not proposal.exists()


def test_native_proposal_cannot_overwrite_release_manifest(tmp_path, monkeypatch):
    path = tmp_path / 'bundled-native-proposal.json'
    path.write_text('original')
    monkeypatch.setattr(artifacts, 'NATIVES', path)
    with pytest.raises(ValueError, match='separate proposal'):
        artifacts.write_native_proposal({}, path)
    assert path.read_text() == 'original'


def test_candidate_observation_still_refuses_invalid_closure(baseline, monkeypatch, tmp_path):
    monkeypatch.setattr(artifacts, 'GROUPS', ('semgrep',))
    monkeypatch.setattr(artifacts, 'TARGETS', (TARGET, 'musllinux_1_2_x86_64'))
    monkeypatch.setattr(artifacts, 'validate_dependencies', lambda *args: None)
    monkeypatch.setattr(artifacts.subprocess, 'run', lambda *args, **kwargs: None)
    def invalid(*args):
        raise ValueError('incomplete dependency lock')
    monkeypatch.setattr(artifacts, 'verify_closure', invalid)
    proposal = tmp_path / 'bundled-native-proposal.json'
    with pytest.raises(ValueError, match='incomplete dependency lock'):
        artifacts.verify_dependencies(baseline, {}, native_proposal=proposal)
    assert not proposal.exists()


@pytest.mark.parametrize('command', ['verify-dependencies', 'lock-dependencies', 'verify', 'install'])
def test_proposal_mode_cannot_be_used_by_release_commands(monkeypatch, command):
    monkeypatch.setattr(artifacts.sys, 'argv', ['scanner_artifacts.py', command,
                                             '--native-proposal', 'bundled-native-proposal.json'])
    with pytest.raises(SystemExit) as error:
        artifacts.main()
    assert error.value.code == 2


@pytest.fixture
def metadata_update(tmp_path):
    candidate = json.loads(artifacts.NATIVES.read_text())
    for rows in candidate['targets'].values():
        for row in rows:
            row.update(version='2.0', wheel='new-wheel.whl', wheel_sha256='f' * 64)
            # PEP 427 spreading removes this prefix at installation.
            if '.data/purelib/' in row['path']:
                row['path'] = 'new-2.0.data/purelib/' + row['path'].split('.data/purelib/', 1)[1]
    proposal = tmp_path / 'bundled-native-proposal.json'
    proposal.write_text(json.dumps(candidate))
    return candidate, proposal, tmp_path / 'bundled-native-libraries.json'


def test_refreshes_exact_native_bytes_in_new_wheels(metadata_update):
    candidate, proposal, destination = metadata_update
    artifacts.refresh_native_metadata(proposal, destination)
    assert json.loads(destination.read_text()) == candidate
    assert not proposal.exists()


@pytest.mark.parametrize('change', ['bytes', 'size', 'owner', 'path', 'add', 'remove',
                                  'duplicate', 'architecture'])
def test_real_native_drift_stays_a_draft_proposal(metadata_update, change):
    candidate, proposal, destination = metadata_update
    rows = candidate['targets'][TARGET]
    if change == 'add':
        row = copy.deepcopy(rows[0])
        row['path'] += '.new'
        rows.append(row)
    elif change == 'remove':
        rows.pop()
    elif change == 'duplicate':
        rows.append(copy.deepcopy(rows[0]))
    elif change == 'architecture':
        candidate['targets'][TARGET] = candidate['targets']['musllinux_1_2_x86_64']
    else:
        field = {'bytes': 'sha256', 'size': 'bytes', 'owner': 'distribution', 'path': 'path'}[change]
        rows[0][field] = rows[0][field] + 1 if field == 'bytes' else 'changed'
    proposal.write_text(json.dumps(candidate))
    original = proposal.read_bytes()
    artifacts.refresh_native_metadata(proposal, destination)
    assert not destination.exists()
    assert proposal.read_bytes() == original


def test_metadata_refresh_still_checks_retained_notices(metadata_update, monkeypatch):
    _, proposal, destination = metadata_update
    def refuse(_):
        raise ValueError('native license missing or changed')
    monkeypatch.setattr(artifacts, 'verify_native_notices', refuse)
    with pytest.raises(ValueError, match='license missing'):
        artifacts.refresh_native_metadata(proposal, destination)
    assert proposal.exists()
    assert not destination.exists()


@pytest.mark.parametrize('fail', [False, True])
def test_candidate_publishes_manifests_together_after_verification(metadata_update, monkeypatch, tmp_path, fail):
    candidate, proposal, native = metadata_update
    original_native = artifacts.NATIVES.read_bytes()
    native.write_bytes(original_native)
    monkeypatch.setattr(artifacts, 'NATIVES', native)
    pins = tmp_path / 'pins.json'
    pins.write_bytes((ROOT / '.github/scanner-versions.json').read_bytes())
    lock = json.loads((ROOT / '.github/semgrep-artifacts.json').read_text())
    output = tmp_path / 'artifacts.json'
    output.write_text('original lock')
    dependencies = tmp_path / 'locks'
    dependencies.mkdir()
    (dependencies / 'manifest.json').write_text('original dependencies')
    proposal.write_text('prior observation')
    originals = {p: p.read_bytes() for p in (pins, output, native, proposal, dependencies / 'manifest.json')}
    monkeypatch.setattr(artifacts, 'candidate', lambda _: lock)
    monkeypatch.setattr(artifacts, 'verify', lambda _: None)
    def generate(_lock, directory, native_proposal):
        assert native_proposal != proposal  # Observation is staged, too.
        (directory / 'manifest.json').write_text('verified dependencies')
        artifacts.write_native_proposal(candidate['targets'], native_proposal)
        if fail:
            raise ValueError('last target closure failed')
    monkeypatch.setattr(artifacts, 'generate_dependencies', generate)
    monkeypatch.setattr(artifacts.sys, 'argv', ['scanner_artifacts.py', 'candidate',
                        '--pins', str(pins), '--lock', str(output), '--dependencies', str(dependencies),
                        '--native-proposal', str(proposal)])
    if fail:
        with pytest.raises(SystemExit) as error:
            artifacts.main()
        assert error.value.code == 1
        assert all(p.read_bytes() == content for p, content in originals.items())
    else:
        artifacts.main()
        assert json.loads(native.read_text()) == candidate
        assert json.loads(output.read_text()) == lock
        assert (dependencies / 'manifest.json').read_text() == 'verified dependencies'
        assert not proposal.exists()
