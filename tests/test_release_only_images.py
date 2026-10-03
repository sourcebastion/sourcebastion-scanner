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
    assert images['if'] == "github.event_name == 'pull_request' || inputs.build_images == true"
    matrix = images['strategy']['matrix']['include']
    assert {item['arch'] for item in matrix} == {'amd64', 'arm64'}
    assert {item['runner'] for item in matrix} == {'ubuntu-latest', 'ubuntu-24.04-arm'}
    aggregate = validation['jobs']['build-docker-standard']
    assert aggregate['needs'] == 'build-scanner'
    assert aggregate['if'].startswith('always()')
    assert aggregate['steps'][0]['run'] == 'test "$BUILD_RESULT" = success'
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
