"""Image validation is required for pull requests and release publication."""

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def workflow(name):
    return yaml.load((ROOT / '.github/workflows' / name).read_text(), Loader=yaml.BaseLoader)


def test_pr_and_release_checks_include_every_image_variant():
    validation = workflow('docker.yml')
    assert 'pull_request' in validation['on']
    assert validation['on']['workflow_dispatch']['inputs']['build_images'] == {
        'description': 'Build and exercise both architectures without publishing',
        'type': 'boolean', 'default': 'false',
    }
    assert validation['on']['workflow_call']['inputs']['build_images'] == {
        'description': 'Validate both architectures before release publication',
        'type': 'boolean', 'default': 'false',
    }
    images = validation['jobs']['build-scanner']
    # Images build on every pull request and on release validation, and may be
    # skipped only on the path classifier's explicit signal. Both halves are
    # required: dropping the first would stop building on PRs, and dropping the
    # second would let any skip through.
    assert "github.event_name == 'pull_request' || inputs.build_images == true" in images['if']
    assert "needs.changes.outputs.image_affecting == 'true'" in images['if']
    assert 'changes' in images['needs']
    # The classifier itself must run wherever the builds would, or its signal
    # is missing exactly when it is needed.
    classifier = validation['jobs']['changes']
    assert classifier['if'] == "github.event_name == 'pull_request' || inputs.build_images == true"
    assert classifier['outputs']['image_affecting']
    matrix = images['strategy']['matrix']['include']
    assert {item['arch'] for item in matrix} == {'amd64', 'arm64'}
    assert {item['runner'] for item in matrix} == {'ubuntu-latest', 'ubuntu-24.04-arm'}
    aggregate = validation['jobs']['build-docker-standard']
    # The gate needs the classifier's result too, so it can tell a legitimate
    # skip from one it should refuse.
    assert set(aggregate['needs']) == {'build-scanner', 'changes'}
    assert aggregate['if'].startswith('always()')
    # Behaviour is asserted by executing the script in
    # tests/test_require_native_image_builds.py; here we only check the wiring,
    # including that the gate is handed all three inputs it decides on.
    gate = aggregate['steps'][-1]
    assert gate['run'] == 'scripts/require-native-image-builds.sh'
    assert gate['env'] == {
        'BUILD_RESULT': '${{ needs.build-scanner.result }}',
        'IMAGE_AFFECTING': '${{ needs.changes.outputs.image_affecting }}',
        'CHANGES_RESULT': '${{ needs.changes.result }}',
    }
    for name in ['lint-python', 'lint-docker', 'lint-rule-fixtures', 'test-unit', 'test-security']:
        assert 'build_images' not in validation['jobs'][name].get('if', '')


def test_release_publication_cannot_bypass_image_validation():
    jobs = workflow('release.yml')['jobs']
    validation = jobs['validate-images']
    assert validation['needs'] == 'prepare-release'
    assert validation['uses'] == './.github/workflows/docker.yml'
    assert validation['with']['build_images'] == 'true'
    for name, job in jobs.items():
        if name.startswith('build-docker-'):
            assert set(job['needs']) == {'prepare-release', 'validate-images'}
            assert 'always()' not in job.get('if', '')
            assert 'continue-on-error' not in job
