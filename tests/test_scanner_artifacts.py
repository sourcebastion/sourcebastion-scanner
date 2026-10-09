"""Artifact verification never converts missing evidence into a green result."""

import importlib.util
import json
from pathlib import Path
import subprocess
from urllib.error import HTTPError

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('scanner_artifacts', ROOT / 'scripts/scanner_artifacts.py')
artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)


@pytest.fixture
def lock():
    return json.loads((ROOT / '.github/semgrep-artifacts.json').read_text())


def test_committed_lock_matches_scanner_version_and_all_targets(lock):
    assert artifacts.validate_lock(lock) == lock
    pins = json.loads((ROOT / '.github/scanner-versions.json').read_text())
    assert lock['version'] == pins['semgrep']['version']


@pytest.mark.parametrize('field,value', [
    ('url', 'https://attacker.example/wheel.whl'),
    ('url', 'http://files.pythonhosted.org/wheel.whl'),
    ('filename', '../escape.whl'), ('sha256', 'not-a-hash'),
])
def test_untrusted_artifact_location_is_rejected(lock, field, value):
    next(iter(lock['artifacts'].values()))[field] = value
    with pytest.raises(ValueError):
        artifacts.validate_lock(lock)


def test_missing_architecture_fails(lock):
    lock['artifacts'].pop(artifacts.TARGETS[0])
    with pytest.raises(ValueError):
        artifacts.validate_lock(lock)


def test_hash_mismatch_never_calls_verifier(lock, tmp_path, monkeypatch):
    monkeypatch.setattr(artifacts, 'fetch', lambda *a: b'tampered')
    monkeypatch.setattr(artifacts.subprocess, 'run', lambda *a, **kw: pytest.fail('must not execute'))
    with pytest.raises(ValueError, match='SHA-256 mismatch'):
        artifacts.verify_artifact(lock, next(iter(lock['artifacts'].values())), tmp_path)
    assert not list(tmp_path.iterdir())


def valid_provenance():
    return {'attestation_bundles': [{
        'publisher': {'kind': 'GitHub', 'repository': artifacts.REPOSITORY,
                      'workflow': artifacts.WORKFLOW},
        'attestations': [{'version': 1}],
    }]}


@pytest.mark.parametrize('bad', ['missing', 'repository', 'workflow', 'kind', 'unsigned'])
def test_missing_or_wrong_publisher_is_rejected(lock, tmp_path, monkeypatch, bad):
    artifact = next(iter(lock['artifacts'].values()))
    provenance = valid_provenance()
    if bad == 'missing':
        provenance = {}
    elif bad == 'unsigned':
        provenance['attestation_bundles'][0]['attestations'] = []
    else:
        provenance['attestation_bundles'][0]['publisher'][bad] = 'untrusted'
    monkeypatch.setattr(artifacts, 'download', lambda *a: tmp_path / artifact['filename'])
    monkeypatch.setattr(artifacts, 'fetch_json', lambda *a: provenance)
    monkeypatch.setattr(artifacts.subprocess, 'run', lambda *a, **kw: pytest.fail('must not execute'))
    with pytest.raises(ValueError):
        artifacts.verify_artifact(lock, artifact, tmp_path)


def test_signature_failure_is_fatal_and_not_retried(lock, tmp_path, monkeypatch):
    artifact = next(iter(lock['artifacts'].values()))
    monkeypatch.setattr(artifacts, 'download', lambda *a: tmp_path / artifact['filename'])
    monkeypatch.setattr(artifacts, 'fetch_json', lambda *a: valid_provenance())
    calls = []

    def reject(command, **kwargs):
        calls.append(command)
        assert kwargs == {'check': True, 'timeout': 180}
        assert '--provenance-file' in command
        assert 'https://github.com/' + artifacts.REPOSITORY in command
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(artifacts.subprocess, 'run', reject)
    with pytest.raises(subprocess.CalledProcessError):
        artifacts.verify_artifact(lock, artifact, tmp_path)
    assert len(calls) == 1


@pytest.mark.parametrize('code,attempts', [(404, 1), (403, 1), (429, 3), (503, 3)])
def test_only_transient_http_errors_are_retried(monkeypatch, code, attempts):
    calls = []

    def fail(*args, **kwargs):
        calls.append(args)
        raise HTTPError(args[0], code, 'failure', {}, None)

    monkeypatch.setattr(artifacts, 'urlopen', fail)
    monkeypatch.setattr(artifacts.time, 'sleep', lambda _: None)
    with pytest.raises(HTTPError):
        artifacts.fetch('https://pypi.org/metadata')
    assert len(calls) == attempts


def test_installer_checks_lock_before_pip(lock, tmp_path, monkeypatch):
    monkeypatch.setattr(artifacts.sys, 'version_info', tuple(map(int, artifacts.PYTHON_FULL.split('.'))))
    monkeypatch.setattr(artifacts.platform, 'machine', lambda: 'x86_64')
    monkeypatch.setattr(artifacts, 'validate_dependencies',
                        lambda *a: (_ for _ in ()).throw(ValueError('dependency lock digest mismatch')))
    monkeypatch.setattr(artifacts.subprocess, 'run', lambda *a, **kw: pytest.fail('pip must not run'))
    with pytest.raises(ValueError, match='digest mismatch'):
        artifacts.install(lock, 'musl')


def test_candidate_requires_all_non_yanked_platforms(lock, monkeypatch):
    urls = [{'filename': a['filename'], 'url': a['url'], 'digests': {'sha256': a['sha256']},
             'yanked': False} for a in lock['artifacts'].values()]
    metadata = {'info': {'version': lock['version']}, 'urls': urls}
    monkeypatch.setattr(artifacts, 'fetch_json', lambda *a: metadata)
    assert artifacts.candidate(lock['version']) == lock
    urls[0]['yanked'] = True
    with pytest.raises(ValueError, match='non-yanked'):
        artifacts.candidate(lock['version'])


def test_candidate_failure_leaves_pins_and_kics_untouched(lock, tmp_path, monkeypatch):
    pins = tmp_path / 'pins.json'
    original = (ROOT / '.github/scanner-versions.json').read_text()
    pins.write_text(original)
    output = tmp_path / 'lock.json'
    monkeypatch.setattr(artifacts, 'candidate', lambda *a: lock)
    monkeypatch.setattr(artifacts, 'verify', lambda *a: (_ for _ in ()).throw(ValueError('invalid evidence')))
    monkeypatch.setattr(artifacts.sys, 'argv', ['scanner_artifacts.py', 'candidate', '--pins', str(pins), '--lock', str(output)])
    with pytest.raises(SystemExit) as error:
        artifacts.main()
    assert error.value.code == 1
    assert pins.read_text() == original
    assert not output.exists()


def test_successful_candidate_updates_semgrep_only(lock, tmp_path, monkeypatch):
    pins = tmp_path / 'pins.json'
    original = json.loads((ROOT / '.github/scanner-versions.json').read_text())
    pins.write_text(json.dumps(original))
    output = tmp_path / 'lock.json'
    monkeypatch.setattr(artifacts, 'candidate', lambda *a: lock)
    monkeypatch.setattr(artifacts, 'verify', lambda *a: None)
    monkeypatch.setattr(artifacts, 'generate_dependencies', lambda *a: None)
    monkeypatch.setattr(artifacts.sys, 'argv', ['scanner_artifacts.py', 'candidate', '--pins', str(pins), '--lock', str(output), '--dependencies', str(tmp_path / 'dependencies')])
    artifacts.main()
    actual = json.loads(pins.read_text())
    assert actual['kics'] == original['kics']
    assert actual['gitleaks'] == original['gitleaks']
    assert actual['grype'] == original['grype']
    assert json.loads(output.read_text()) == lock


def test_release_and_merge_exercise_are_fail_closed():
    def workflow(name):
        return yaml.load((ROOT / '.github/workflows' / name).read_text(), Loader=yaml.BaseLoader)
    release = workflow('release.yml')['jobs']
    assert release['prepare-release']['needs'] == 'verify-scanner-artifacts'
    assert release['verify-scanner-artifacts']['uses'] == './.github/workflows/scanner-integrity.yml'
    verify = workflow('scanner-integrity.yml')
    assert verify['on']['pull_request']['branches'] == ['main']
    # Closed set on purpose: artifact verification must not gain an
    # unreviewed trigger. `merge_group` is admitted because a merge queue is
    # a pre-merge gate exactly like a pull request, and a required check that
    # cannot report there would stall every merge.
    assert set(verify['on']) == {'pull_request', 'merge_group', 'workflow_dispatch', 'workflow_call'}
    assert verify['permissions'] == {'contents': 'read'}
    assert all('continue-on-error' not in s for s in verify['jobs']['verify']['steps'])
    update = workflow('scanner-artifact-update.yml')
    assert update['on']['schedule']
    assert update['jobs']['propose']['if'] == "github.ref == 'refs/heads/main'"


def test_weekly_updates_use_scoped_existing_app_not_actions_identity():
    text = (ROOT / '.github/workflows/scanner-artifact-update.yml').read_text()
    workflow = yaml.load(text, Loader=yaml.BaseLoader)
    assert workflow['permissions'] == {'contents': 'read'}
    job = workflow['jobs']['propose']
    assert job['if'] == "github.ref == 'refs/heads/main'"
    assert job['environment'] == 'scanner-maintenance'
    assert 'permissions' not in job
    steps = job['steps']
    mint = next(s for s in steps if s.get('id') == 'app-token')
    assert mint['uses'] == 'actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1'
    assert mint['if'] == "steps.changes.outputs.changed == 'true'"
    # Scope must not depend on the event payload. The action scopes a token to
    # the current repository only when BOTH `owner` and `repositories` are
    # unset; `owner` set with an empty `repositories` scopes it to *every*
    # repository in that owner's installation. `github.event.repository.name`
    # is populated for workflow_dispatch but is not guaranteed for `schedule`,
    # so relying on it risks org-wide Contents and Pull requests write on the
    # weekly run — silently, and in the wrong direction.
    assert mint['with'] == {
        'app-id': '${{ secrets.SOURCEBASTION_BOT_APP_ID }}',
        'private-key': '${{ secrets.SOURCEBASTION_BOT_PRIVATE_KEY }}',
        'permission-contents': 'write',
        'permission-pull-requests': 'write',
    }
    assert 'owner' not in mint['with'], 'owner without a literal repository list over-scopes'
    assert not any('github.event' in value for value in mint['with'].values())
    assert steps.index(mint) > next(i for i, s in enumerate(steps)
                                   if s.get('run', '').startswith('python -m pytest'))
    publish = steps[-1]
    assert publish['if'] == mint['if']
    assert publish['env']['GH_TOKEN'] == '${{ steps.app-token.outputs.token }}'
    assert "if [ \"$APP_SLUG\" != 'sourcebastion-bot' ]" in publish['run']
    assert 'gh workflow run' not in text
    assert 'gh pr merge' not in text
    assert 'gh pr review' not in text
    assert '${{ github.token }}' not in text


def test_release_images_install_locked_wheel():
    for name in ('Dockerfile',):
        content = (ROOT / 'images' / name).read_text()
        assert 'scanner_artifacts.py install --libc' in content
        assert 'pip install --no-cache-dir semgrep' not in content
