"""A published baseline must be bound to the exact base source before use."""
import json
from pathlib import Path
import runpy
import sys
import subprocess
import shutil
import tarfile
import pytest
import re

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


@pytest.mark.parametrize('failure', [None, 'attestation', 'archive-identity'])
def test_published_base_is_attested_and_copied_by_digest_before_loading(tmp_path, monkeypatch, failure):
    # Reuse the real small OCI archive fixture; exercise actual byte verification.
    archive = runpy.run_path(str(ROOT / 'tests/test_inventory_maintenance.py'))['oci'](tmp_path)
    with tarfile.open(archive) as bundle:
        descriptor = json.load(bundle.extractfile('index.json'))['manifests'][0]
    expected = descriptor['digest']
    if failure == 'archive-identity':
        descriptor = dict(descriptor, digest='sha256:' + 'a' * 64)
    tool = runpy.run_path(str(ROOT / 'scripts/prepare-upgrade-base.py'))
    raw = json.dumps({'schemaVersion': 2, 'manifests': [dict(descriptor,
        platform={'architecture': 'arm64', 'os': 'linux'})]}).encode()
    calls = []
    def command(argv, **kwargs):
        calls.append(argv)
        if argv[:3] == ['skopeo', 'inspect', '--raw']: return raw
        if argv[:3] == ['gh', 'attestation', 'verify'] and failure == 'attestation':
            raise subprocess.CalledProcessError(1, argv)
        if argv[:2] == ['skopeo', 'copy']:
            shutil.copyfile(archive, argv[-1].removeprefix('oci-archive:'))
        return b'[]'
    monkeypatch.setattr(tool['prepare'].__globals__['subprocess'], 'check_output', command)
    if failure:
        with pytest.raises((ValueError, subprocess.CalledProcessError)):
            tool['prepare']('b' * 40, 'arm64', tmp_path)
        assert not any(cmd[0] == 'docker' for cmd in calls)
        return
    tool['prepare']('b' * 40, 'arm64', tmp_path)
    verify = next(cmd for cmd in calls if cmd[:3] == ['gh', 'attestation', 'verify'])
    assert verify[verify.index('--source-digest') + 1] == 'b' * 40
    assert '--deny-self-hosted-runners' in verify
    copied = next(cmd for cmd in calls if cmd[:2] == ['skopeo', 'copy'])
    assert '--preserve-digests' in copied and '@sha256:' in copied[-2]
    assert copied[-2].endswith('@' + expected)
    assert calls.index(verify) < calls.index(copied)


def test_release_baseline_reuse_is_required_and_errors_never_silently_rebuild():
    import yaml
    workflow = yaml.load((ROOT / '.github/workflows/docker.yml').read_text(), Loader=yaml.BaseLoader)
    steps = workflow['jobs']['build-scanner']['steps']
    script = next(step['run'] for step in steps if step.get('name') == 'Enforce added compressed release layers')
    assert 'prepare-upgrade-base.py --source "$BASE_SHA"' in script
    assert "elif grep -Eqi 'not found|manifest unknown|no such manifest'" in script
    assert 'cat "$RUNNER_TEMP/base-lookup.txt" >&2' in script
    assert 'scripts/verify-inventory-release-size.py' in script
    assert '--candidate "$RUNNER_TEMP/inventory-candidate.oci.tar"' in script
    assert workflow['jobs']['build-scanner']['permissions']['attestations'] == 'read'
    caller = yaml.load((ROOT / '.github/workflows/release.yml').read_text(), Loader=yaml.BaseLoader)
    assert caller['jobs']['validate-images']['permissions']['attestations'] == 'read'


def test_unpublished_baseline_build_args_run_with_real_python(tmp_path):
    import yaml
    workflow = yaml.load((ROOT / '.github/workflows/docker.yml').read_text(), Loader=yaml.BaseLoader)
    script = next(step['run'] for step in workflow['jobs']['build-scanner']['steps']
                  if step.get('name') == 'Enforce added compressed release layers')
    # Execute exactly what Bash passes to -c, without repairing its indentation.
    program = re.search(r"python3 -c '([^']*)'", script).group(1)
    arguments = {'PYTHON_BASE_IMAGE': 'python@sha256:' + 'a' * 64,
                 'ALPINE_BASE_IMAGE': 'alpine@sha256:' + 'b' * 64}
    path = tmp_path / 'inventory-base-args.json'
    path.write_text(json.dumps(arguments))
    # Python3.14 CLI now dedents -c; Ubuntu's system python3 does not. Compile the
    # exact text explicitly so a newer developer interpreter cannot mask this.
    result = subprocess.run([sys.executable, '-c',
                             'import sys; program=sys.argv.pop(1); exec(compile(program,"workflow","exec"))',
                             program, str(path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [part for name, value in arguments.items()
                                          for part in ('--build-arg', name + '=' + value)]
