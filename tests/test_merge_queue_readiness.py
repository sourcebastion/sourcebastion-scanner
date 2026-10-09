"""Every required check must be able to report in the merge queue.

A merge queue evaluates the same required status checks as a pull request, in a
`merge_group` event. A workflow that does not trigger on `merge_group`, or a job
whose condition excludes it, never reports -- and the queue waits forever. A
stalled queue blocks every merge in the repository, so this is asserted rather
than remembered.
"""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]

#: Required check name -> the workflow that produces it. Mirrors branch
#: protection on `main`; a check added there must be added here.
REQUIRED = {
    'Lint Python Code': 'docker.yml',
    'Lint Dockerfiles': 'docker.yml',
    'Lint Rule Fixtures': 'docker.yml',
    'Unit Tests': 'docker.yml',
    'Security Tests': 'docker.yml',
    'Build Standard Docker Image': 'docker.yml',
    'Security Scan': 'github-scan.yml',
    'version-check': 'github-scan.yml',
    'Self-Scan': 'self-scan.yml',
    'CodeQL (${{ matrix.language }})': 'security.yml',
}

#: Checks that cannot run in a merge queue at all. `actions/dependency-review-action`
#: needs a pull request's dependency diff, which a merge group does not have.
#: Enabling a queue while this is a *required* check would stall every merge, so
#: it has to be dropped from the required set at that point -- it still runs on
#: pull requests, where its review value is.
PULL_REQUEST_ONLY = {'Dependency review'}


def workflow(name):
    return yaml.safe_load((ROOT / '.github/workflows' / name).read_text())


def triggers(document):
    on = document.get('on', document.get(True))
    return set(on) if isinstance(on, dict) else {on} if isinstance(on, str) else set(on)


@pytest.mark.parametrize('check,name', sorted(REQUIRED.items()))
def test_each_required_check_runs_in_the_merge_queue(check, name):
    document = workflow(name)
    assert 'merge_group' in triggers(document), f"{name} must trigger on merge_group"

    jobs = {job.get('name', key): job for key, job in document['jobs'].items()}
    assert check in jobs, f"{check} not found in {name}"
    condition = jobs[check].get('if', '')
    if condition:
        assert 'merge_group' in condition, (
            f"{check} has a condition that does not admit merge_group: {condition}"
        )


def test_the_pull_request_only_check_is_identified_and_still_pull_request_scoped():
    """Documents the one check that blocks enabling a queue, so the constraint
    is discoverable rather than discovered by stalling the repository."""
    jobs = workflow('security.yml')['jobs']
    review = {job.get('name', key): job for key, job in jobs.items()}['Dependency review']

    assert review['if'] == "github.event_name == 'pull_request'"
    assert 'Dependency review' in PULL_REQUEST_ONLY


def test_the_native_builds_and_their_gate_admit_the_merge_queue():
    """The queue is the last gate before a commit lands, so it must build."""
    jobs = workflow('docker.yml')['jobs']

    for key in ('changes', 'build-scanner', 'build-docker-standard'):
        assert 'merge_group' in jobs[key]['if'], key
