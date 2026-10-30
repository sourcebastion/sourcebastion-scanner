"""Reuse an attested exact-source published baseline without rebuilding lost APKs."""
import argparse
import hashlib
import subprocess
from pathlib import Path

from inventory_release import oci_layers
from m046_published import IMAGE, native_descriptor


def prepare(source, architecture, output):
    raw = subprocess.check_output(['skopeo', 'inspect', '--raw', 'docker://' + IMAGE + ':' + source], timeout=60)
    index = 'sha256:' + hashlib.sha256(raw).hexdigest()
    descriptor = native_descriptor(raw, index, architecture)
    # Resolve the mutable source tag once, then verify and copy immutable bytes.
    verified = subprocess.check_output(['gh', 'attestation', 'verify', 'oci://' + IMAGE + '@' + index,
        '--repo', 'sourcebastion/sourcebastion-scanner', '--source-digest', source,
        '--signer-workflow', 'sourcebastion/sourcebastion-scanner/.github/workflows/release.yml',
        '--deny-self-hosted-runners', '--format', 'json'], timeout=120)
    (output / 'inventory-base-attestation.json').write_bytes(verified)
    native = IMAGE + '@' + descriptor['digest']
    archive = output / 'inventory-base.oci.tar'
    subprocess.check_output(['skopeo', 'copy', '--preserve-digests', 'docker://' + native,
                             'oci-archive:' + str(archive)], timeout=900)
    if oci_layers(archive, architecture)['manifest_digest'] != descriptor['digest']:
        raise ValueError('published-base-archive-mismatch')
    subprocess.check_output(['docker', 'pull', '--platform', 'linux/' + architecture, native], timeout=900)
    subprocess.check_output(['docker', 'tag', native, 'sourcebastion:inventory-upgrade-base'], timeout=30)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--architecture', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    prepare(args.source, args.architecture, args.output)
