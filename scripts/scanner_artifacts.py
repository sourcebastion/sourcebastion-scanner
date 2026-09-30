"""Reviewable Semgrep artifact locks; fail-closed release verification.

Hashes identify bytes. PyPI attestations authenticate the allowed publisher.
KICS is deliberately not updated until its publisher provenance is established.
"""

import argparse
import hashlib
import json
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


def install(lock, libc):
    """Install only the hashed wheel already approved by the release verifier.

    Transitive Python dependencies are not covered by this artifact lock.
    """
    validate_lock(lock)
    arch = {'amd64': 'x86_64', 'arm64': 'aarch64'}.get(platform.machine(), platform.machine())
    target = ('musllinux_1_2_' if libc == 'musl' else 'manylinux_2_34_') + arch
    if target not in lock['artifacts']:
        raise ValueError('unsupported Semgrep architecture')
    with tempfile.TemporaryDirectory(prefix='sourcebastion-install-') as directory:
        wheel = download(lock['artifacts'][target], Path(directory))
        subprocess.run([sys.executable, '-m', 'pip', 'install', '--no-cache-dir', str(wheel)], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('candidate', 'verify', 'install'))
    parser.add_argument('--version')
    parser.add_argument('--libc', choices=('musl', 'glibc'))
    parser.add_argument('--lock', type=Path, default=LOCK)
    parser.add_argument('--pins', type=Path, default=PINS)
    args = parser.parse_args()
    try:
        pins = json.loads(args.pins.read_text())
        if args.command == 'candidate':
            lock = candidate(args.version)
            verify(lock)
            # Nothing is written until every selected artifact is verified.
            args.lock.write_text(json.dumps(lock, indent=2) + '\n')
            pins['semgrep']['version'] = lock['version']
            args.pins.write_text(json.dumps(pins, indent=2) + '\n')
        else:
            lock = validate_lock(json.loads(args.lock.read_text()))
            if lock['version'] != pins['semgrep']['version']:
                raise ValueError('artifact lock and scanner version disagree')
            if args.command == 'verify':
                verify(lock)
            else:
                if not args.libc:
                    raise ValueError('--libc is required for installation')
                install(lock, args.libc)
        print(f"Semgrep {lock['version']}: {args.command} completed; KICS pin unchanged")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        parser.exit(1, f'scanner artifact verification failed: {exc}\n')


if __name__ == '__main__':
    main()
