"""Keep build retries bounded, non-publishing, and fail-closed."""

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def read_yaml(path):
    return yaml.load((ROOT / path).read_text(), Loader=yaml.BaseLoader)


def test_retry_attempts_preserve_inputs_and_fail_on_exhaustion():
    action = read_yaml('.github/actions/build-with-retry/action.yml')
    steps = action['runs']['steps']
    attempts = [step for step in steps if 'uses' in step]
    assert [step['id'] for step in attempts] == ['first', 'second', 'third']
    assert len({step['uses'] for step in attempts}) == 1
    assert attempts[0]['with'] == attempts[1]['with'] == attempts[2]['with']
    assert attempts[0]['with']['push'] == 'false'
    assert 'if' not in attempts[0]
    assert attempts[0]['continue-on-error'] == 'true'
    assert attempts[1]['continue-on-error'] == 'true'
    assert 'continue-on-error' not in attempts[2]
    for step, previous in zip(attempts[1:], ['first', 'second']):
        assert step['if'] == "${{ !cancelled() && steps.%s.outcome == 'failure' }}" % previous
    delays = [step for step in steps if 'run' in step]
    assert len(delays) == 2
    for delay, attempt, seconds in zip(delays, attempts[1:], [15, 30]):
        assert delay['if'] == attempt['if']
        assert f'sleep {seconds}' in delay['run']
    assert action['outputs']['digest']['value'] == (
        '${{ steps.third.outputs.digest || steps.second.outputs.digest || steps.first.outputs.digest }}'
    )


def test_standard_build_uses_retries_without_bypassing_tests():
    workflow = read_yaml('.github/workflows/docker.yml')
    job = workflow['jobs']['build-scanner']
    assert job['timeout-minutes'] == '60'
    steps = job['steps']
    builds = [step for step in steps if step.get('uses') == './.github/actions/build-with-retry']
    assert len(builds) == 1
    assert builds[0]['id'] == 'build'
    assert builds[0]['with']['platforms'] == 'linux/${{ matrix.arch }}'
    assert builds[0]['with']['cache-to'] == 'type=gha,scope=scanner-${{ matrix.arch }},mode=max'
    assert builds[0]['with']['load'] == 'true'
    assert 'PYTHON_VERSION=' in builds[0]['with']['build-args']
    assert all('continue-on-error' not in step for step in steps)
    test_steps = [step for step in steps if step.get('run') and 'docker run' in step['run']]
    assert len(test_steps) >= 2
    assert all('if' not in step for step in test_steps)
