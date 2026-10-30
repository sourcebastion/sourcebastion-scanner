"""Qualifying bot updates flow automatically; broader changes need review."""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import runpy
from urllib.error import HTTPError

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
policy = runpy.run_path(str(ROOT / 'scripts/automated_scanner_update.py'))
runtime = runpy.run_path(str(ROOT / 'scripts/prepare-inventory-node.py'))


@pytest.fixture
def versions():
    paths = policy['FIXED']
    old = {path: (ROOT / path).read_text() for path in paths}
    new = deepcopy(old)
    scanners = json.loads(new['.github/scanner-versions.json'])
    scanners['semgrep']['version'] = '99.0.0'
    new['.github/scanner-versions.json'] = json.dumps(scanners)
    major, minor, patch = map(int, old['VERSION'].strip().split('.'))
    version = f'{major}.{minor}.{patch + 1}'
    new['VERSION'] = version + '\n'
    notes = old['CHANGELOG.md']
    position = notes.index('## [')
    new['CHANGELOG.md'] = notes[:position] + f'## [{version}] - 2026-10-29\n\nVerified scanner updates.\n\n' + notes[position:]
    return old, new


def test_verified_data_and_next_patch_are_eligible(versions):
    old, new = versions
    assert policy['eligible'](list(new), old.__getitem__, new.__getitem__)
    native = json.loads(new['.github/bundled-native-libraries.json'])
    for rows in native['targets'].values():
        for row in rows:
            row['wheel_sha256'] = 'b' * 64  # New wheel; identical installed native bytes.
    new['.github/bundled-native-libraries.json'] = json.dumps(native)
    assert policy['eligible'](list(new), old.__getitem__, new.__getitem__)


@pytest.mark.parametrize('change', ['code', 'proposal', 'native', 'owner', 'path', 'kics', 'version', 'history', 'runtime-lock'])
def test_unqualified_changes_take_manual_path(versions, change):
    old, new = versions
    paths = list(new)
    if change in {'code', 'proposal'}:
        paths.append('scripts/scanner_artifacts.py' if change == 'code' else '.github/bundled-native-proposal.json')
    elif change in {'native', 'owner', 'path'}:
        native = json.loads(new['.github/bundled-native-libraries.json'])
        row = next(iter(native['targets'].values()))[0]
        row[{'native': 'sha256', 'owner': 'distribution', 'path': 'path'}[change]] = 'changed'
        new['.github/bundled-native-libraries.json'] = json.dumps(native)
    elif change == 'kics':
        scanners = json.loads(new['.github/scanner-versions.json']); scanners['kics']['image'] = 'changed'
        new['.github/scanner-versions.json'] = json.dumps(scanners)
    elif change == 'version':
        new['VERSION'] = '99.0.0'
    elif change == 'history':
        new['CHANGELOG.md'] += 'changed history'
    else:
        manifest = json.loads(new['.github/python-locks/manifest.json'])
        manifest['files'][next(k for k in manifest['files'] if k.startswith('runtime-'))] = 'changed'
        new['.github/python-locks/manifest.json'] = json.dumps(manifest)
    assert not policy['eligible'](paths, old.__getitem__, new.__getitem__)


def pr():
    return {'number': 217, 'user': {'login': 'sourcebastion-bot[bot]'}, 'merged_at': 'now',
            'merge_commit_sha': 'a' * 40, 'draft': False,
            'base': {'ref': 'main', 'repo': {'full_name': policy['REPOSITORY']}},
            'head': {'ref': policy['PREFIX'] + 'test', 'repo': {'full_name': policy['REPOSITORY']}}}


@pytest.mark.parametrize('field', ['author', 'sha', 'draft', 'fork', 'branch'])
def test_release_requires_exact_merged_owned_bot_pr(field):
    value = pr()
    assert policy['trusted_pr'](value, 'a' * 40)
    if field == 'author': value['user']['login'] = 'human'
    if field == 'sha': value['merge_commit_sha'] = 'b' * 40
    if field == 'draft': value['draft'] = True
    if field == 'fork': value['head']['repo']['full_name'] = 'other/scanner'
    if field == 'branch': value['head']['ref'] = 'unrelated'
    assert not policy['trusted_pr'](value, 'a' * 40)


def test_failed_bot_candidate_is_refreshed_but_human_work_is_preserved():
    value = pr()
    assert policy['candidate_branch']([value], lambda _: [{'author': value['user']}]) == value['head']['ref']
    with pytest.raises(ValueError, match='preserve'):
        policy['candidate_branch']([value], lambda _: [{'author': {'login': 'human'}}])


def test_retained_apks_rebuild_when_upstream_has_disappeared(tmp_path, monkeypatch):
    pins = json.loads((ROOT / '.github/inventory-runtime-pins.json').read_text())
    raw = b'verified retained package'
    for row in pins['packages'].values(): row['sha256']['x86_64'] = hashlib.sha256(raw).hexdigest()
    path = tmp_path / 'pins.json'; path.write_text(json.dumps(pins))
    calls = []
    def fetch(url, **_):
        calls.append(url)
        if 'alpinelinux.org' in url: raise HTTPError(url, 404, 'removed', {}, None)
        return io.BytesIO(raw)
    monkeypatch.setitem(runtime['prepare'].__globals__, 'urlopen', fetch)
    runtime['prepare'](path, tmp_path / 'apks', 'x86_64')
    assert len(calls) == 2 and all('/releases/download/runtime-apks-' in url for url in calls)
    assert (tmp_path / 'apks/nodejs-24.22.1-r1.apk').read_bytes() == raw


def test_missing_mirror_falls_back_only_to_exact_source_but_mismatch_never_falls_back(tmp_path, monkeypatch):
    pins = json.loads((ROOT / '.github/inventory-runtime-pins.json').read_text())
    calls = []
    def fetch(url, **_):
        calls.append(url)
        if 'github.com' in url: raise HTTPError(url, 404, 'absent', {}, None)
        raise HTTPError(url, 404, 'removed', {}, None)
    monkeypatch.setitem(runtime['prepare'].__globals__, 'urlopen', fetch)
    path = tmp_path / 'pins'; path.write_text(json.dumps(pins))
    with pytest.raises(ValueError, match='input-unavailable'):
        runtime['prepare'](path, tmp_path / 'missing', 'x86_64')
    assert len(calls) == 2 and calls[-1].endswith('nodejs-24.22.1-r1.apk')
    calls.clear()
    def corrupt(url, **_): calls.append(url); return io.BytesIO(b'wrong')
    monkeypatch.setitem(runtime['prepare'].__globals__, 'urlopen', corrupt)
    with pytest.raises(ValueError, match='digest-mismatch'):
        runtime['prepare'](path, tmp_path / 'bad', 'x86_64')
    assert len(calls) == 1


def test_workflows_preserve_check_and_release_boundaries():
    load = lambda name: yaml.load((ROOT / '.github/workflows' / name).read_text(), Loader=yaml.BaseLoader)
    updater = load('scanner-artifact-update.yml')
    assert updater['jobs']['propose']['needs'] == 'retain-runtime'
    steps = updater['jobs']['propose']['steps']
    merge = steps[-1]
    assert '--auto --squash --match-head-commit' in merge['run']
    assert '--admin' not in merge['run']
    assert "steps.policy.outputs.draft == 'false'" in merge['if']
    candidate = next(step for step in steps if step.get('id') == 'candidate')
    assert candidate['with']['draft'] == '${{ steps.policy.outputs.draft }}'
    release = load('release.yml')['jobs']
    assert release['release-policy']['permissions'] == {'contents': 'read', 'pull-requests': 'read'}
    assert release['prepare-release']['environment'] == '${{ needs.release-policy.outputs.environment }}'
    retain = load('runtime-inputs.yml')['jobs']['retain']
    assert "github.ref == 'refs/heads/main'" in retain['if']
    assert '--clobber' not in retain['steps'][-1]['run']
    assert '--latest=false' in retain['steps'][-1]['run']


@pytest.mark.parametrize('proposal', ['absent', 'present', 'deleted'])
def test_candidate_stages_generated_files_when_optional_proposal_is_absent(tmp_path, proposal):
    import os
    import subprocess
    workflow = yaml.load((ROOT / '.github/workflows/scanner-artifact-update.yml').read_text(), Loader=yaml.BaseLoader)
    steps = workflow['jobs']['propose']['steps']
    candidate = next(step for step in steps if step.get('id') == 'candidate')
    repository = tmp_path / 'repository'
    repository.mkdir()

    def git(*args):
        return subprocess.run(['git', *args], cwd=repository, capture_output=True, text=True, check=True)

    git('init', '-q')
    git('config', 'user.name', 'staging-test')
    git('config', 'user.email', 'staging@example.invalid')
    required = {'.github/scanner-versions.json', '.github/semgrep-artifacts.json',
                '.github/python-locks/manifest.json', '.github/bundled-native-libraries.json',
                'VERSION', 'CHANGELOG.md'}
    optional = '.github/bundled-native-proposal.json'
    for name in required | ({optional} if proposal == 'deleted' else set()):
        path = repository / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('previous\n')
    git('add', '.')
    git('commit', '-qm', 'reviewed baseline')
    for name in required:
        (repository / name).write_text('verified update\n')
    if proposal == 'present':
        (repository / optional).write_text('{}\n')
    elif proposal == 'deleted':
        (repository / optional).unlink()
    (repository / (optional + '.unreviewed')).write_text('preserve outside allowlist\n')
    output = tmp_path / 'github-output'
    output.touch()
    selector = next((step for step in steps if step.get('id') == 'optional_proposal'), None)
    if selector:
        subprocess.run(['bash', '-eu', '-o', 'pipefail', '-c', selector['run']], cwd=repository,
                       env=dict(os.environ, GITHUB_OUTPUT=str(output)), check=True, capture_output=True, text=True)
    values = dict(line.split('=', 1) for line in output.read_text().splitlines())
    paths = candidate['with']['add-paths'].replace('${{ steps.optional_proposal.outputs.path }}', values.get('path', ''))
    git('add', '--', *[line.strip() for line in paths.splitlines() if line.strip()])
    expected = required | ({optional} if proposal != 'absent' else set())
    assert set(git('diff', '--cached', '--name-only').stdout.splitlines()) == expected
    assert '?? ' + optional + '.unreviewed' in git('status', '--porcelain').stdout


@pytest.mark.parametrize('event,actor,qualified,expected', [
    ('workflow_dispatch', 'jfelten', True, 'release'),
    ('repository_dispatch', 'other-bot[bot]', True, 'release'),
    ('repository_dispatch', 'sourcebastion-bot[bot]', False, 'release'),
    ('repository_dispatch', 'sourcebastion-bot[bot]', True, 'scanner-maintenance'),
])
def test_actual_release_classifier_defaults_to_protected_environment(
        tmp_path, monkeypatch, versions, event, actor, qualified, expected):
    old, new = versions
    function = policy['main']; scope = function.__globals__
    output = tmp_path / 'output'
    for key, value in {'GITHUB_EVENT_NAME': event, 'GITHUB_ACTOR': actor,
                       'GITHUB_REF': 'refs/heads/main', 'GITHUB_SHA': 'a' * 40,
                       'GITHUB_OUTPUT': str(output)}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setitem(scope, 'git_read', lambda ref: old.__getitem__ if ref.endswith('^') else new.__getitem__)
    def command(argv, **_):
        if argv[0] == 'gh': return json.dumps([pr()]).encode()
        assert argv[:4] == ['git', 'diff', '--no-renames', '--name-only']
        return '\n'.join(list(new) + ([] if qualified else ['images/Dockerfile']))
    monkeypatch.setattr(scope['subprocess'], 'check_output', command)
    function()
    assert output.read_text() == f'environment={expected}\n'
