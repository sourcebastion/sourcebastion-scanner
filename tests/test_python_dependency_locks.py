"""The dependency lock is complete, target-specific, and fail closed."""

import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('scanner_artifacts', ROOT / 'scripts/scanner_artifacts.py')
artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)


@pytest.fixture
def lock():
    return json.loads((ROOT / '.github/semgrep-artifacts.json').read_text())


def test_all_committed_dependency_locks_match_manifest(lock):
    artifacts.validate_dependencies(artifacts.DEPENDENCIES, lock)


def test_runtime_inputs_cover_local_package_without_executing_setup():
    tree = ast.parse((ROOT / 'setup.py').read_text())
    setup = next(n for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name) and n.func.id == 'setup')
    expected = ast.literal_eval(next(k.value for k in setup.keywords if k.arg == 'install_requires'))
    actual = [line for line in (ROOT / 'scripts/python-runtime.in').read_text().splitlines()
              if line and not line.startswith('#')]
    assert set(actual) == set(expected)


@pytest.mark.parametrize('text', [
    'requests>=2\n', 'requests==2.0\n', '--extra-index-url https://attacker.example\n',
    'requests @ https://attacker.example/requests.whl\n',
    'requests==2.0 --hash=md5:' + 'a' * 32,
    'requests==2.0 ; python_version > "3" --hash=sha256:' + 'a' * 64,
])
def test_unsafe_requirements_are_rejected(lock, text):
    with pytest.raises(ValueError):
        artifacts.dependency_text(text, 'runtime', artifacts.TARGETS[0], lock)


def test_semgrep_must_match_attested_wheel(lock):
    target = artifacts.TARGETS[0]
    artifact = lock['artifacts'][target]
    text = f"semgrep @ {artifact['url']} --hash=sha256:{artifact['sha256']}\n"
    assert artifacts.dependency_text(text, 'semgrep', target, lock) == text
    with pytest.raises(ValueError, match='hash must match'):
        artifacts.dependency_text(text.replace(artifact['sha256'], '0' * 64), 'semgrep', target, lock)


def test_changed_lock_file_fails_before_install(lock, tmp_path):
    shutil.copytree(artifacts.DEPENDENCIES, tmp_path / 'locks')
    path = tmp_path / 'locks' / artifacts.lock_name('runtime', artifacts.TARGETS[0])
    path.write_text(path.read_text() + '\n# edited\n')
    with pytest.raises(ValueError, match='digest mismatch'):
        artifacts.validate_dependencies(tmp_path / 'locks', lock)


def test_python_mismatch_is_not_silently_resolved(lock, monkeypatch):
    monkeypatch.setattr(artifacts.sys, 'version_info', (3, 12))
    monkeypatch.setattr(artifacts.subprocess, 'run', lambda *a, **k: pytest.fail('must not install'))
    with pytest.raises(ValueError, match='CPython 3.11'):
        artifacts.install(lock, 'glibc')


def test_installer_enforces_hashes_wheels_and_closure(lock, monkeypatch):
    monkeypatch.setattr(artifacts.sys, 'version_info', (3, 11))
    monkeypatch.setattr(artifacts.platform, 'machine', lambda: 'x86_64')
    calls = []
    monkeypatch.setattr(artifacts.subprocess, 'run', lambda command, **kw: calls.append(command))
    artifacts.install(lock, 'glibc')
    assert '--require-hashes' in calls[0]
    assert '--only-binary=:all:' in calls[0]
    assert '--force-reinstall' in calls[0]
    assert '--no-deps' not in calls[0]
    assert calls[1][-2:] == ['pip', 'check']


def test_failed_dependency_refresh_preserves_all_reviewed_files(lock, tmp_path, monkeypatch):
    pins = tmp_path / 'pins.json'
    original = (ROOT / '.github/scanner-versions.json').read_bytes()
    pins.write_bytes(original)
    output = tmp_path / 'artifacts.json'
    output.write_text(json.dumps(lock))
    deps = tmp_path / 'locks'
    deps.mkdir()
    (deps / 'sentinel').write_text('reviewed')
    monkeypatch.setattr(artifacts, 'candidate', lambda *a: lock)
    monkeypatch.setattr(artifacts, 'verify', lambda *a: None)

    def fail(_lock, directory):
        (directory / 'incomplete').write_text('partial')
        raise ValueError('target has no wheel')

    monkeypatch.setattr(artifacts, 'generate_dependencies', fail)
    monkeypatch.setattr(artifacts.sys, 'argv', ['scanner_artifacts.py', 'candidate',
                        '--pins', str(pins), '--lock', str(output), '--dependencies', str(deps)])
    with pytest.raises(SystemExit):
        artifacts.main()
    assert pins.read_bytes() == original
    assert json.loads(output.read_text()) == lock
    assert [p.name for p in deps.iterdir()] == ['sentinel']


def test_real_pip_rejects_tampered_wheel_without_installing(tmp_path):
    # No network, mocked hash checker, or executable package code.
    wheel = tmp_path / 'sourcebastion_probe-1.0-py3-none-any.whl'
    with zipfile.ZipFile(wheel, 'w') as archive:
        archive.writestr('sourcebastion_probe-1.0.dist-info/METADATA',
                         'Metadata-Version: 2.1\nName: sourcebastion-probe\nVersion: 1.0\n')
        archive.writestr('sourcebastion_probe-1.0.dist-info/WHEEL',
                         'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n')
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    requirements = tmp_path / 'requirements.txt'
    requirements.write_text(f'{wheel} --hash=sha256:{digest}\n')
    with zipfile.ZipFile(wheel, 'a') as archive:
        archive.writestr('tampered.txt', 'substitution')
    result = subprocess.run([sys.executable, '-m', 'pip', '--isolated', 'download', '--no-index',
                             '--no-deps', '--require-hashes', '--only-binary=:all:',
                             '-r', str(requirements), '--dest', str(tmp_path / 'download')],
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert 'DO NOT MATCH THE HASHES' in result.stderr


def test_all_scanner_images_disable_unlocked_python_downloads():
    for name in ('Dockerfile', 'Dockerfile.thin', 'Dockerfile.slim', 'Dockerfile.semgrep', 'Dockerfile.micro'):
        text = (ROOT / 'images' / name).read_text()
        assert '--group build' in text
        assert 'build --no-isolation' in text
        assert '--no-index --no-deps' in text
        assert 'pip install --no-cache-dir -r' not in text
        assert 'pip install --no-cache-dir -e' not in text
        # The locks must also be *reachable*. Four images copy the script to
        # /opt and pass explicit paths; micro copies the whole context and
        # relies on ROOT defaults. Either is fine, and an edit that copies the
        # script without the locks is not — it would pass every other
        # assertion here and fail only at release, because image builds are
        # deliberately release-only.
        explicit = '--dependencies' in text and 'python-locks' in text
        whole_context = 'COPY . .' in text
        assert explicit or whole_context, name


def test_weekly_refresh_includes_dependency_only_updates():
    text = (ROOT / '.github/workflows/scanner-artifact-update.yml').read_text()
    assert 'uv==0.11.0' in text
    assert 'git diff --quiet -- .github/scanner-versions.json .github/semgrep-artifacts.json .github/python-locks' in text
    assert 'git add .github/scanner-versions.json .github/semgrep-artifacts.json .github/python-locks' in text
    assert '${version}-${lock_digest}' in text
    # A digest in the branch name must not defeat the single-candidate guard:
    # matching the full name would open a second PR beside the one under
    # review every time a transitive dependency moved.
    assert 'startswith("bot/semgrep-artifacts-")' in text
    assert 'gh pr list --head' not in text


def make_metadata_wheel(directory, name, version='1.0', requires=()):
    with zipfile.ZipFile(directory / f'{name}-{version}-py3-none-any.whl', 'w') as archive:
        archive.writestr(f'{name}-{version}.dist-info/METADATA',
                         f'Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n'
                         + ''.join(f'Requires-Dist: {req}\n' for req in requires))


def test_closure_checks_target_markers_and_extras(lock, tmp_path, monkeypatch):
    source = tmp_path / 'scripts'
    source.mkdir()
    (source / 'python-runtime.in').write_text('root[cli]==1.0\n')
    monkeypatch.setattr(artifacts, 'ROOT', tmp_path)
    wheels = tmp_path / 'wheels'
    wheels.mkdir()
    make_metadata_wheel(wheels, 'root', requires=[
        'child>=1; python_version < "3.12" and platform_machine == "aarch64"',
        'cli>=1; extra == "cli"',
        'windows-only; sys_platform == "win32"',
    ])
    make_metadata_wheel(wheels, 'cli')
    # Host is x86_64 / Python 3.13 in local tests; target must still require child.
    with pytest.raises(ValueError, match='incomplete dependency lock: child'):
        artifacts.verify_closure(wheels, 'runtime', artifacts.TARGETS[1], lock)
    make_metadata_wheel(wheels, 'child')
    artifacts.verify_closure(wheels, 'runtime', artifacts.TARGETS[1], lock)


def test_closure_rejects_incompatible_dependency(lock, tmp_path, monkeypatch):
    source = tmp_path / 'scripts'
    source.mkdir()
    (source / 'python-runtime.in').write_text('root>=2\n')
    monkeypatch.setattr(artifacts, 'ROOT', tmp_path)
    make_metadata_wheel(tmp_path, 'root', version='1.0')
    with pytest.raises(ValueError, match='incompatible locked dependency'):
        artifacts.verify_closure(tmp_path, 'runtime', artifacts.TARGETS[0], lock)
