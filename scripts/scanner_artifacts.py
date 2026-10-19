"""Reviewable Semgrep artifact locks; fail-closed release verification.

Hashes identify bytes. PyPI attestations authenticate the allowed publisher.
KICS is deliberately not updated until its publisher provenance is established.
"""

import argparse
from collections import Counter
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
import zipfile
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
NATIVES = ROOT / '.github/bundled-native-libraries.json'
NOTICES = ROOT / 'third-party-notices'
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


def verify_dependencies(directory, lock, native_proposal=None):
    validate_dependencies(directory, lock)
    observed = {}
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
                if group == 'semgrep' and target.startswith('musllinux_'):
                    if native_proposal is None:
                        verify_native_notices(verify_bundled_natives(wheels, target))
                    else:
                        observed[target] = bundled_natives(wheels)
    if native_proposal is not None:
        write_native_proposal(observed, native_proposal)


def bundled_natives(wheels):
    """Read bundled shared libraries as ZIP data; never load or execute them.

    Inspect every wheel in the resolved runtime closure, not only the four
    distributions previously known to vendor libraries. Extension modules are
    not the separately vendored libraries tracked by M049.
    """
    from email.parser import BytesParser
    from packaging.utils import canonicalize_name

    result = []
    for wheel in sorted(wheels.glob('*.whl')):
        with zipfile.ZipFile(wheel) as archive:
            members = archive.namelist()
            if len(members) != len(set(members)):
                raise ValueError('duplicate wheel member: ' + wheel.name)
            metadata = [p for p in members if p.count('/') == 1
                        and p.endswith('.dist-info/METADATA')]
            if len(metadata) != 1:
                raise ValueError('wheel must contain exactly one metadata record')
            item = BytesParser().parsebytes(archive.read(metadata[0]))
            if not item['Name'] or not item['Version']:
                raise ValueError('missing wheel distribution identity')
            wheel_digest = None
            for member in sorted(members):
                path = Path(member)
                vendored = any(part.endswith('.libs') for part in path.parts[:-1])
                vendored |= '/semgrep/bin/libs/' in '/' + member
                vendored |= path.name.startswith('lib') and '.so' in path.name
                if member.endswith('/') or not vendored or '.so' not in path.name:
                    continue
                raw = archive.read(member)
                if not raw.startswith(b'\x7fELF'):
                    raise ValueError('bundled library is not ELF: ' + member)
                if wheel_digest is None:
                    wheel_digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
                result.append({'distribution': canonicalize_name(item['Name']),
                               'version': item['Version'], 'wheel': wheel.name,
                               'wheel_sha256': wheel_digest, 'path': member,
                               'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    return result


def verify_bundled_natives(wheels, target):
    """A reviewed lock bump cannot silently change vendored native bytes."""
    manifest = json.loads(NATIVES.read_text())
    if (manifest.get('schema_version') != 1
            or set(manifest.get('targets', {})) != {t for t in TARGETS if t.startswith('musllinux_')}):
        raise ValueError('invalid bundled native manifest targets')
    expected = manifest['targets'][target]
    observed = bundled_natives(wheels)
    if observed != expected:
        old = {(row['wheel'], row['path'], row['sha256']) for row in expected}
        new = {(row['wheel'], row['path'], row['sha256']) for row in observed}
        raise ValueError('bundled native library drift for ' + target
                         + '; removed/changed=' + repr(sorted(old - new))
                         + '; added/changed=' + repr(sorted(new - old))
                         + '; review manifest, notices and source coverage before updating')
    return observed


def validate_native_proposal_path(path):
    if (path.name != 'bundled-native-proposal.json' or path.is_symlink()
            or path.resolve() == NATIVES.resolve()):
        raise ValueError('native proposal must be a separate proposal file')


def write_native_proposal(observed, path):
    """Candidate-only data for review; never replace the release baseline.

    Publisher identity, wheel hashes and dependency closure still must pass.
    Changed native bytes leave release verification red until separately reviewed.
    """
    validate_native_proposal_path(path)
    baseline = json.loads(NATIVES.read_text())
    targets = {t for t in TARGETS if t.startswith('musllinux_')}
    if (baseline.get('schema_version') != 1 or set(baseline.get('targets', {})) != targets
            or set(observed) != targets):
        raise ValueError('invalid bundled native proposal targets')
    # Existing retained licenses must remain valid even for a proposal.
    for libraries in baseline['targets'].values():
        verify_native_notices(libraries)
    if observed == baseline['targets']:
        path.unlink(missing_ok=True)
        print('Bundled native libraries unchanged on both architectures')
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({'schema_version': 1, 'targets': observed}, indent=2) + '\n')
    print('NATIVE REVIEW REQUIRED: ' + str(path)
          + '; proposed bytes only; release baseline, notices and source pins unchanged')


def refresh_native_metadata(proposal, destination):
    """Stage new wheel bindings only when the reviewed native set is identical.

    Wheel spreading removes the versioned .data/{purelib,platlib} prefix.
    Compare installed paths, owners, sizes and hashes on each architecture;
    counts matter, so duplicate entries cannot conceal a removed library.
    New bytes, owners or paths remain a proposal requiring source/notice review.
    """
    if not proposal.exists():
        return
    baseline = json.loads(NATIVES.read_text())
    candidate = json.loads(proposal.read_text())
    targets = {t for t in TARGETS if t.startswith('musllinux_')}
    if any(value.get('schema_version') != 1 or set(value.get('targets', {})) != targets
           for value in (baseline, candidate)):
        raise ValueError('invalid bundled native update targets')

    def identity(row):
        path = re.sub(r'^[^/]+\.data/(?:purelib|platlib)/', '', row['path'])
        return row['distribution'], path, row['bytes'], row['sha256']

    for target in targets:
        old, new = baseline['targets'][target], candidate['targets'][target]
        if Counter(map(identity, old)) != Counter(map(identity, new)):
            return
    for rows in candidate['targets'].values():
        verify_native_notices(rows)
    destination.write_text(json.dumps(candidate, indent=2) + '\n')
    proposal.unlink()
    print('Bundled native bytes unchanged on both architectures; refreshed wheel bindings')


def verify_native_notices(libraries):
    """Require retained, unchanged license files for each bundled byte set.

    Notice coverage is not corresponding-source or release acceptance.
    """
    manifest = json.loads((NOTICES / 'manifest.json').read_text())
    if manifest.get('schema_version') != 1 or not isinstance(manifest.get('components'), list):
        raise ValueError('invalid native notice manifest')
    covered = set()
    names = set()
    for component in manifest['components']:
        name = component['id']
        if not re.fullmatch(r'[a-z0-9][a-z0-9.+-]*', name) or name in names:
            raise ValueError('invalid or duplicate native notice component')
        names.add(name)
        if (NOTICES / name).is_symlink():
            raise ValueError('native notice directory must not be a symlink')
        if not component['license_files'] or not component['license']:
            raise ValueError('native component has no retained license')
        for filename, digest in component['license_files'].items():
            if Path(filename).name != filename or filename in ('.', '..'):
                raise ValueError('invalid native license filename')
            path = NOTICES / name / filename
            if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError('native license missing or changed: ' + name + '/' + filename)
        if not component['source_url'].startswith('https://') or not re.fullmatch(
                r'[0-9a-f]{64}', component['source_sha256']):
            raise ValueError('native component has no pinned upstream source reference')
        for digest in component['native_sha256']:
            if not re.fullmatch(r'[0-9a-f]{64}', digest) or digest in covered:
                raise ValueError('invalid or ambiguous native notice binding')
            covered.add(digest)
    missing = {row['sha256'] for row in libraries} - covered
    if missing:
        raise ValueError('bundled native bytes lack retained notices: ' + repr(sorted(missing)))
    return covered


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


def generate_dependencies(lock, directory, native_proposal=None):
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
    if native_proposal is None:
        verify_dependencies(directory, lock)
    else:
        verify_dependencies(directory, lock, native_proposal=native_proposal)


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
    parser.add_argument('--native-proposal', type=Path,
                        help='candidate only: report native drift without changing the release baseline')
    parser.add_argument('--libc', choices=('musl', 'glibc'))
    parser.add_argument('--lock', type=Path, default=LOCK)
    parser.add_argument('--pins', type=Path, default=PINS)
    parser.add_argument('--dependencies', type=Path, default=DEPENDENCIES)
    parser.add_argument('--group', choices=GROUPS, default='semgrep')
    args = parser.parse_args()
    if args.native_proposal is not None and args.command != 'candidate':
        parser.error('--native-proposal is allowed only for candidate discovery')
    try:
        pins = json.loads(args.pins.read_text())
        if args.command == 'candidate':
            lock = candidate(args.version)
            verify(lock)
            # Stage every target and verify publisher/hash/closure before proposing files.
            # Stage native bindings too; verification failures publish no candidate files.
            with tempfile.TemporaryDirectory(prefix='sourcebastion-candidate-') as temporary:
                staged = Path(temporary) / 'python-locks'
                staged.mkdir()
                proposal = Path(temporary) / 'bundled-native-proposal.json'
                native_manifest = Path(temporary) / NATIVES.name
                if args.native_proposal is None:
                    generate_dependencies(lock, staged)
                else:
                    validate_native_proposal_path(args.native_proposal)
                    generate_dependencies(lock, staged, native_proposal=proposal)
                    refresh_native_metadata(proposal, native_manifest)
                args.dependencies.mkdir(parents=True, exist_ok=True)
                for path in staged.iterdir():
                    (args.dependencies / path.name).write_bytes(path.read_bytes())
                if native_manifest.exists():
                    NATIVES.write_bytes(native_manifest.read_bytes())
                if args.native_proposal is not None:
                    if proposal.exists():
                        args.native_proposal.parent.mkdir(parents=True, exist_ok=True)
                        args.native_proposal.write_bytes(proposal.read_bytes())
                    else:
                        args.native_proposal.unlink(missing_ok=True)
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
