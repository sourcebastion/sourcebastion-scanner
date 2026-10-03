"""Reviewable Semgrep artifact locks; fail-closed release verification.

Hashes identify bytes. PyPI attestations authenticate the allowed publisher.
KICS is deliberately not updated until its publisher provenance is established.
"""

import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import urlopen


REPOSITORY = 'semgrep/semgrep-proprietary'
WORKFLOW = 'pro-release.yml'
TARGETS = ('manylinux_2_34_x86_64', 'manylinux_2_34_aarch64',
           'musllinux_1_2_x86_64', 'musllinux_1_2_aarch64')
ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / '.github/semgrep-artifacts.json'
PINS = ROOT / '.github/scanner-versions.json'
DEPENDENCIES = ROOT / '.github/python-locks'
def configure_python(version):
    global PYTHON_FULL, PYTHON, ABI
    if not re.fullmatch(r'3\.[0-9]+\.[0-9]+', version):
        raise ValueError('PYTHON_VERSION must be an exact stable Python 3 version')
    PYTHON_FULL = version
    PYTHON = '.'.join(version.split('.')[:2])
    ABI = 'cp' + PYTHON.replace('.', '')


configure_python((ROOT / 'PYTHON_VERSION').read_text().strip())
GROUPS = ('build', 'runtime', 'semgrep')


def lock_name(group, target):
    return f'{group}-{ABI}-{target}.txt'


def pip_platforms(target):
    family, major, minor, arch = target.split('_', 3)
    # pip's explicit --platform does not expand compatible older libc tags.
    platforms = [f'{family}_{major}_{n}_{arch}' for n in range(int(minor), 0, -1)]
    if family == 'manylinux':
        platforms.append('manylinux2014_' + arch)
    return [arg for value in platforms for arg in ('--platform', value)]


def dependency_text(text, group, target, lock):
    """Accept only exact, hash-pinned packages; never pip options or source URLs."""
    lines = [line for line in text.replace('\\\n', ' ').splitlines()
             if line.strip() and not line.startswith('#')]
    names = set()
    for line in lines:
        fields = line.split()
        requirement = fields.pop(0)
        if requirement == 'semgrep':
            artifact = lock['artifacts'][target]
            if fields[:2] != ['@', artifact['url']]:
                raise ValueError('Semgrep dependency lock must use the attested artifact')
            fields = fields[2:]
            if fields != ['--hash=sha256:' + artifact['sha256']]:
                raise ValueError('Semgrep dependency hash must match attested artifact')
            name = 'semgrep'
        else:
            match = re.fullmatch(r'([a-z0-9][a-z0-9-]*)==([a-zA-Z0-9.!+_-]+)', requirement)
            if not match:
                raise ValueError('dependency must have an exact version and no markers/options')
            name = match[1]
        if not fields or any(not re.fullmatch(r'--hash=sha256:[0-9a-f]{64}', f) for f in fields):
            raise ValueError('every dependency requires SHA-256 hashes')
        if name in names:
            raise ValueError('duplicate dependency')
        names.add(name)
    if not names or ('semgrep' in names) != (group == 'semgrep'):
        raise ValueError('wrong dependency group')
    return text


def validate_dependencies(directory, lock):
    metadata = json.loads((directory / 'manifest.json').read_text())
    expected = {lock_name(group, target) for group in GROUPS for target in TARGETS}
    if (metadata.get('schema_version') != 1 or metadata.get('python') != PYTHON_FULL
            or metadata.get('semgrep_version') != lock['version']
            or set(metadata.get('files', {})) != expected):
        raise ValueError('dependency manifest does not match Python/Semgrep/targets')
    for group in GROUPS:
        for target in TARGETS:
            name = lock_name(group, target)
            data = (directory / name).read_bytes()
            if hashlib.sha256(data).hexdigest() != metadata['files'][name]:
                raise ValueError('dependency lock digest mismatch: ' + name)
            dependency_text(data.decode(), group, target, lock)
    return metadata


def verify_dependencies(directory, lock):
    validate_dependencies(directory, lock)
    with tempfile.TemporaryDirectory(prefix='sourcebastion-wheels-') as temporary:
        for group in GROUPS:
            for target in TARGETS:
                wheels = Path(temporary) / f'{group}-{target}'
                wheels.mkdir()
                subprocess.run([
                    sys.executable, '-m', 'pip', '--isolated', 'download',
                    '--index-url', 'https://pypi.org/simple', '--require-hashes',
                    '--only-binary=:all:', '--no-deps', '--python-version', PYTHON_FULL,
                    '--implementation', 'cp', '--abi', ABI, '--abi', 'abi3', '--abi', 'none',
                    *pip_platforms(target), '--dest', str(wheels),
                    '-r', str(directory / lock_name(group, target)),
                ], check=True, timeout=600)
                verify_closure(wheels, group, target, lock)


def verify_closure(wheels, group, target, lock):
    """Check wheel metadata using TARGET markers, not the verifier host's Python/arch."""
    from email.parser import BytesParser
    import zipfile
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name
    from packaging.version import Version

    metadata = {}
    for wheel in wheels.glob('*.whl'):
        with zipfile.ZipFile(wheel) as archive:
            paths = [p for p in archive.namelist()
                     if p.count('/') == 1 and p.endswith('.dist-info/METADATA')]
            if len(paths) != 1:
                raise ValueError('wheel must contain exactly one metadata record')
            item = BytesParser().parsebytes(archive.read(paths[0]))
        name = canonicalize_name(item['Name'])
        if name in metadata:
            raise ValueError('duplicate wheel for dependency: ' + name)
        metadata[name] = item
    marker_env = {
        'implementation_name': 'cpython', 'implementation_version': PYTHON_FULL,
        'os_name': 'posix', 'platform_machine': 'aarch64' if target.endswith('aarch64') else 'x86_64',
        'platform_python_implementation': 'CPython', 'platform_release': '', 'platform_system': 'Linux',
        'platform_version': '', 'python_full_version': PYTHON_FULL, 'python_version': PYTHON,
        'sys_platform': 'linux', 'extra': '',
    }
    source = ROOT / 'scripts' / ('python-build.in' if group == 'build' else 'python-runtime.in')
    pending = [Requirement(line) for line in source.read_text().splitlines() if line and not line.startswith('#')]
    if group == 'semgrep':
        pending.append(Requirement('semgrep==' + lock['version']))
    visited = set()
    while pending:
        requirement = pending.pop()
        name = canonicalize_name(requirement.name)
        if name not in metadata:
            raise ValueError('incomplete dependency lock: ' + name)
        item = metadata[name]
        if Version(item['Version']) not in requirement.specifier:
            raise ValueError('incompatible locked dependency: ' + str(requirement))
        if requirement.url:
            raise ValueError('dependency metadata must not introduce direct URLs')
        for extra in {''} | set(requirement.extras):
            if (name, extra) in visited:
                continue
            visited.add((name, extra))
            for raw in item.get_all('Requires-Dist', []):
                child = Requirement(raw)
                if child.marker is None or child.marker.evaluate({**marker_env, 'extra': extra}):
                    pending.append(child)


def generate_dependencies(lock, directory):
    """Resolve target markers without running candidate code; verify before publication."""
    directory.mkdir(parents=True, exist_ok=True)
    metadata = {'schema_version': 1, 'python': PYTHON_FULL, 'semgrep_version': lock['version'], 'files': {}}
    with tempfile.TemporaryDirectory(prefix='sourcebastion-resolve-') as temporary:
        for group in GROUPS:
            for target in TARGETS:
                source = ROOT / 'scripts' / ('python-build.in' if group == 'build' else 'python-runtime.in')
                content = source.read_text()
                if group == 'semgrep':
                    artifact = lock['artifacts'][target]
                    content += f"\nsemgrep @ {artifact['url']}#sha256={artifact['sha256']}\n"
                input_file = Path(temporary) / 'requirements.in'
                input_file.write_text(content)
                arch = target.rsplit('_', 1)[-1] if target.endswith('aarch64') else 'x86_64'
                uv_platform = arch + ('-unknown-linux-musl' if target.startswith('musl') else '-manylinux_2_34')
                # No ambient index/build configuration can introduce private or source packages.
                env = {k: v for k, v in os.environ.items() if not k.startswith(('UV_', 'PIP_'))}
                command = [
                    sys.executable, '-m', 'uv', '--no-config', '--no-cache', 'pip', 'compile',
                    str(input_file), '--python-version', PYTHON_FULL, '--python-platform', uv_platform,
                    '--no-python-downloads', '--generate-hashes', '--no-header', '--no-annotate',
                    '--only-binary=:all:', '--default-index', 'https://pypi.org/simple',
                ]
                try:
                    result = subprocess.run(command, env=env, check=True, capture_output=True, text=True, timeout=600)
                except subprocess.CalledProcessError as exc:
                    raise ValueError(f'dependency resolution failed for {group}/{target}: {exc.stderr}') from exc
                text = result.stdout
                # uv retains URL hash fragments; pip's explicit hash remains authoritative.
                if group == 'semgrep':
                    text = text.replace('#sha256=' + artifact['sha256'], '')
                dependency_text(text, group, target, lock)
                name = lock_name(group, target)
                data = text.encode()
                (directory / name).write_bytes(data)
                metadata['files'][name] = hashlib.sha256(data).hexdigest()
    (directory / 'manifest.json').write_text(json.dumps(metadata, indent=2) + '\n')
    verify_dependencies(directory, lock)


def fetch(url, limit=200 * 1024 * 1024):
    """Only transport errors and retryable HTTP responses get three attempts."""
    for attempt in range(3):
        try:
            with urlopen(url, timeout=60) as response:
                if urlparse(response.url).hostname != urlparse(url).hostname:
                    raise ValueError('cross-host redirect rejected')
                data = response.read(limit + 1)
                if len(data) > limit:
                    raise ValueError('artifact exceeds download limit')
                return data
        except HTTPError as exc:
            if exc.code not in (429, 500, 502, 503, 504) or attempt == 2:
                raise
        except (URLError, TimeoutError, ConnectionError):
            if attempt == 2:
                raise
        time.sleep((5, 15)[attempt])
    # Unreachable: the final attempt re-raises in both handlers. Stated so a
    # later edit to either cannot turn an exhausted retry into a silent None,
    # which every caller would then treat as artifact bytes.
    raise AssertionError('retries exhausted without raising')


def fetch_json(url):
    return json.loads(fetch(url, 8 * 1024 * 1024))


def validate_lock(lock):
    if lock.get('schema_version') != 1 or lock.get('project') != 'semgrep':
        raise ValueError('unsupported artifact lock')
    version = lock.get('version', '')
    if not isinstance(version, str) or not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('exact stable Semgrep version required')
    if set(lock.get('artifacts', {})) != set(TARGETS):
        raise ValueError('all Linux architectures and libc variants are required')
    for target, artifact in lock['artifacts'].items():
        name = artifact['filename']
        url = urlparse(artifact['url'])
        if (not name.startswith(f'semgrep-{version}-') or '/' in name or '\\' in name
                or not name.endswith(f'-{target}.whl')):
            raise ValueError('wheel filename does not match locked version/target')
        if (url.scheme != 'https' or url.netloc != 'files.pythonhosted.org'
                or url.query or url.fragment or not url.path.endswith('/' + name)):
            raise ValueError('only exact PyPI artifact URLs are permitted')
        if not re.fullmatch(r'[0-9a-f]{64}', artifact['sha256']):
            raise ValueError('invalid SHA-256')
    return lock


def candidate(version=None):
    metadata = fetch_json('https://pypi.org/pypi/semgrep/' + (version + '/' if version else '') + 'json')
    version = metadata['info']['version']
    artifacts = {}
    for target in TARGETS:
        matches = [item for item in metadata['urls']
                   if item['filename'].endswith(f'-{target}.whl') and not item.get('yanked')]
        if len(matches) != 1:
            raise ValueError(f'expected one non-yanked wheel for {target}')
        item = matches[0]
        artifacts[target] = {'filename': item['filename'], 'url': item['url'],
                             'sha256': item['digests']['sha256']}
    return validate_lock({'schema_version': 1, 'project': 'semgrep',
                          'version': version, 'artifacts': artifacts})


def download(artifact, directory):
    data = fetch(artifact['url'])
    if hashlib.sha256(data).hexdigest() != artifact['sha256']:
        raise ValueError('artifact SHA-256 mismatch')
    path = directory / artifact['filename']
    path.write_bytes(data)
    return path


def verify_artifact(lock, artifact, directory):
    wheel = download(artifact, directory)
    provenance = fetch_json(
        f"https://pypi.org/integrity/semgrep/{lock['version']}/{artifact['filename']}/provenance"
    )
    bundles = provenance.get('attestation_bundles', [])
    if not bundles:
        raise ValueError('missing publisher attestations')
    for bundle in bundles:
        publisher = bundle.get('publisher', {})
        if (publisher.get('kind') != 'GitHub'
                or publisher.get('repository') != REPOSITORY
                or publisher.get('workflow') != WORKFLOW
                or not bundle.get('attestations')):
            raise ValueError('unexpected publisher repository/workflow or missing attestation')
    provenance_path = directory / (wheel.name + '.provenance.json')
    provenance_path.write_text(json.dumps(provenance), encoding='utf-8')
    # The verifier binds the publisher policy to the signing certificate and
    # verifies the wheel digest, signature and transparency-log evidence.
    # Never retry or ignore a cryptographic/publisher verification failure.
    subprocess.run([
        sys.executable, '-m', 'pypi_attestations', 'verify', 'pypi',
        '--repository', 'https://github.com/' + REPOSITORY,
        '--provenance-file', str(provenance_path), str(wheel),
    ], check=True, timeout=180)


def verify(lock):
    validate_lock(lock)
    with tempfile.TemporaryDirectory(prefix='sourcebastion-verify-') as directory:
        for artifact in lock['artifacts'].values():
            verify_artifact(lock, artifact, Path(directory))


def install(lock, libc, directory=DEPENDENCIES, group='semgrep'):
    """Install the complete reviewed, wheel-only Python environment."""
    validate_lock(lock)
    if platform.python_implementation() != 'CPython' or tuple(sys.version_info[:3]) != tuple(map(int, PYTHON_FULL.split('.'))):
        raise ValueError('dependency locks require CPython ' + PYTHON_FULL)
    arch = {'amd64': 'x86_64', 'arm64': 'aarch64'}.get(platform.machine(), platform.machine())
    target = ('musllinux_1_2_' if libc == 'musl' else 'manylinux_2_34_') + arch
    if target not in lock['artifacts']:
        raise ValueError('unsupported Semgrep architecture')
    validate_dependencies(directory, lock)
    subprocess.run([sys.executable, '-m', 'pip', '--isolated', 'install', '--no-cache-dir',
                    '--index-url', 'https://pypi.org/simple', '--require-hashes',
                    '--only-binary=:all:', '--force-reinstall',
                    '-r', str(directory / lock_name(group, target))], check=True, timeout=600)
    subprocess.run([sys.executable, '-m', 'pip', 'check'], check=True, timeout=60)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('candidate', 'verify', 'install', 'lock-dependencies', 'verify-dependencies'))
    parser.add_argument('--version')
    parser.add_argument('--libc', choices=('musl', 'glibc'))
    parser.add_argument('--lock', type=Path, default=LOCK)
    parser.add_argument('--pins', type=Path, default=PINS)
    parser.add_argument('--dependencies', type=Path, default=DEPENDENCIES)
    parser.add_argument('--group', choices=GROUPS, default='semgrep')
    args = parser.parse_args()
    try:
        pins = json.loads(args.pins.read_text())
        if args.command == 'candidate':
            lock = candidate(args.version)
            verify(lock)
            # Do not change reviewed files until every target dependency set verifies.
            with tempfile.TemporaryDirectory(prefix='sourcebastion-candidate-') as temporary:
                staged = Path(temporary)
                generate_dependencies(lock, staged)
                args.dependencies.mkdir(parents=True, exist_ok=True)
                for path in staged.iterdir():
                    (args.dependencies / path.name).write_bytes(path.read_bytes())
            args.lock.write_text(json.dumps(lock, indent=2) + '\n')
            pins['semgrep']['version'] = lock['version']
            args.pins.write_text(json.dumps(pins, indent=2) + '\n')
        else:
            lock = validate_lock(json.loads(args.lock.read_text()))
            if lock['version'] != pins['semgrep']['version']:
                raise ValueError('artifact lock and scanner version disagree')
            if args.command == 'verify':
                verify(lock)
            elif args.command == 'verify-dependencies':
                verify_dependencies(args.dependencies, lock)
            elif args.command == 'lock-dependencies':
                verify(lock)
                with tempfile.TemporaryDirectory(prefix='sourcebastion-candidate-') as temporary:
                    staged = Path(temporary)
                    generate_dependencies(lock, staged)
                    args.dependencies.mkdir(parents=True, exist_ok=True)
                    for path in staged.iterdir():
                        (args.dependencies / path.name).write_bytes(path.read_bytes())
            else:
                if not args.libc:
                    raise ValueError('--libc is required for installation')
                install(lock, args.libc, args.dependencies, args.group)
        print(f"Semgrep {lock['version']}: {args.command} completed; KICS pin unchanged")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        parser.exit(1, f'scanner artifact verification failed: {exc}\n')


if __name__ == '__main__':
    main()
