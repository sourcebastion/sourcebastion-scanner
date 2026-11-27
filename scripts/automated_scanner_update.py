"""Conservative eligibility for the existing bot's generated Semgrep updates.

GitHub owns checks, merging and release sequencing. This only classifies data;
unknown changes take the existing protected manual release path.
"""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import subprocess

REPOSITORY = 'sourcebastion/sourcebastion-scanner'
PREFIX = 'bot/semgrep-artifacts-'
FIXED = {'.github/scanner-versions.json', '.github/semgrep-artifacts.json',
         '.github/bundled-native-libraries.json', '.github/python-locks/manifest.json',
         'VERSION', 'CHANGELOG.md'}


def allowed(path):
    return path in FIXED or bool(re.fullmatch(
        r'\.github/python-locks/semgrep-cp[0-9]+-(?:manylinux_2_34|musllinux_1_2)_(?:x86_64|aarch64)\.txt', path))


def generated_candidate_path(path):
    """Refresh generated runtime locks without granting automatic release authority."""
    return (allowed(path) or path == '.github/bundled-native-proposal.json'
            or bool(re.fullmatch(
                r'\.github/python-locks/runtime-cp[0-9]+-(?:manylinux_2_34|musllinux_1_2)_(?:x86_64|aarch64)\.txt', path)))


def eligible(paths, before, after):
    if not paths or not all(allowed(path) for path in paths):
        return False
    try:
        old = json.loads(before('.github/scanner-versions.json'))
        new = json.loads(after('.github/scanner-versions.json'))
        previous, current = old.pop('semgrep'), new.pop('semgrep')
        if old != new or set(current) != {'version'}:
            return False
        if not all(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', row['version']) for row in (previous, current)):
            return False
        if tuple(map(int, current['version'].split('.'))) < tuple(map(int, previous['version'].split('.'))):
            return False
        old_manifest = json.loads(before('.github/python-locks/manifest.json'))
        new_manifest = json.loads(after('.github/python-locks/manifest.json'))
        for manifest in (old_manifest, new_manifest):
            manifest.pop('semgrep_version')
            manifest['files'] = {k: v for k, v in manifest['files'].items() if not k.startswith('semgrep-')}
        if old_manifest != new_manifest:
            return False
        def natives(read):
            value = json.loads(read('.github/bundled-native-libraries.json'))
            if value['schema_version'] != 1:
                raise ValueError('unknown native schema')
            return {target: Counter((row['distribution'],
                re.sub(r'^[^/]+\.data/(?:purelib|platlib)/', '', row['path']), row['bytes'], row['sha256'])
                for row in rows) for target, rows in value['targets'].items()}
        if natives(before) != natives(after):
            return False
        # No version or release-note edits outside the next patch and one entry.
        if 'VERSION' in paths or 'CHANGELOG.md' in paths:
            version = before('VERSION').strip()
            major, minor, patch = map(int, version.split('.'))
            next_version = f'{major}.{minor}.{patch + 1}'
            if after('VERSION').strip() != next_version:
                return False
            old_notes, new_notes = before('CHANGELOG.md'), after('CHANGELOG.md')
            heading = re.search(r'^## \[?[0-9]', old_notes, re.MULTILINE)
            if heading is None:
                return False
            prefix, history = old_notes[:heading.start()], old_notes[heading.start():]
            if not new_notes.startswith(prefix) or not new_notes.endswith(history):
                return False
            entry = new_notes[len(prefix):-len(history)]
            if not re.fullmatch(r'## \[' + re.escape(next_version) + r'\] - [0-9]{4}-[0-9]{2}-[0-9]{2}\n\n[^\0]+\n\n', entry):
                return False
            if len(re.findall(r'^## ', entry, re.MULTILINE)) != 1:
                return False
        return True
    except (ValueError, KeyError, TypeError):
        return False


def trusted_pr(pr, sha):
    return (pr['user']['login'] == 'sourcebastion-bot[bot]' and pr['merged_at']
            and pr['merge_commit_sha'] == sha and not pr['draft']
            and pr['base']['ref'] == 'main' and pr['head']['ref'].startswith(PREFIX)
            and pr['head']['repo']['full_name'] == REPOSITORY
            and pr['base']['repo']['full_name'] == REPOSITORY)


def git_read(ref):
    return lambda path: subprocess.check_output(['git', 'show', f'{ref}:{path}'], text=True)


ABSENT = '0' * 40


def bot_only(pr, history):
    """True when the bot opened the pull request and wrote every commit up to its head."""
    return (pr['user']['login'] == 'sourcebastion-bot[bot]'
            and (pr['head'].get('repo') or {}).get('full_name') == REPOSITORY
            and bool(history) and len(history) < 100
            and history[-1].get('sha') == pr['head']['sha']
            and all((row.get('author') or {}).get('login') == 'sourcebastion-bot[bot]' for row in history))


def generated_only(files):
    return len(files) < 100 and all(generated_candidate_path(row['filename']) for row in files)


def candidate_branch(prs, commits):
    candidates = [pr for pr in prs if pr['head']['ref'].startswith(PREFIX)]
    if len(candidates) > 1:
        raise ValueError('multiple bot candidates require reconciliation')
    if not candidates:
        return PREFIX + 'update'
    pr = candidates[0]
    if not bot_only(pr, commits(pr)):
        raise ValueError('candidate has human or unknown work; preserve it for review')
    return pr['head']['ref']


def leftover_branch_is_refreshable(closed, head_sha, commits, files):
    """Allow reuse of a candidate branch that has no open pull request.

    A merged bot candidate may be reused. So may one closed without merging
    (for example, as stale), if only the bot wrote it, it changed only generated
    files, and nobody pushed after the close: GitHub keeps that head at
    refs/pull/<number>/head, so a refresh loses nothing. Any other leftover
    branch is preserved for review.
    """
    if not closed or closed[0]['head']['sha'] != head_sha:
        return False
    if closed[0]['user']['login'] != 'sourcebastion-bot[bot]':
        return False
    if closed[0]['merged_at']:
        return True
    return bot_only(closed[0], commits(closed[0])) and generated_only(files(closed[0]))


# A pre-push hook sees each remote ref's advertised value, and the server only
# applies the update if the ref still has that value. Requiring it to equal the
# tip prepare_candidate validated binds the candidate action's force-push to
# that tip, whatever the action fetched in between.
PUSH_GUARD = """#!/bin/sh
# Generated by scripts/automated_scanner_update.py --install-push-guard.
status=0
while read -r local_ref local_oid remote_ref remote_oid; do
  if [ "$remote_ref" != "refs/heads/{branch}" ] || [ "$remote_oid" != "{lease}" ]; then
    echo "push refused: $remote_ref is at $remote_oid; validated refs/heads/{branch} at {lease}" >&2
    status=1
  fi
done
exit "$status"
"""


def install_push_guard(branch, lease, hooks, repo=Path('.')):
    """Allow only a push that replaces the validated tip (or creates an absent branch)."""
    if not re.fullmatch(re.escape(PREFIX) + r'[A-Za-z0-9._-]+', branch) or not re.fullmatch(r'[0-9a-f]{40}', lease):
        raise ValueError('invalid candidate branch or lease')
    hooks.mkdir(mode=0o700, parents=True, exist_ok=True)
    hook = hooks / 'pre-push'
    hook.write_text(PUSH_GUARD.format(branch=branch, lease=lease))
    hook.chmod(0o700)
    subprocess.check_call(['git', '-C', str(repo), 'config', '--local', 'core.hooksPath', str(hooks)])


def prepare_candidate():
    if os.environ['APP_SLUG'] != 'sourcebastion-bot':
        raise ValueError('expected existing sourcebastion-bot App')
    def api(path):
        return json.loads(subprocess.check_output(['gh', 'api', f'repos/{REPOSITORY}/{path}']))
    prs = api('pulls?state=open&base=main&per_page=100')
    if len(prs) >= 100:
        raise ValueError('candidate list truncated; preserve existing work for review')
    def commits(pr):
        return api(f"pulls/{pr['number']}/commits?per_page=100")
    def files(pr):
        return api(f"pulls/{pr['number']}/files?per_page=100")
    branch = candidate_branch(prs, commits)
    open_candidate = next((pr for pr in prs if pr['head']['ref'] == branch), None)
    if open_candidate is not None:
        lease = open_candidate['head']['sha']
        if not generated_only(files(open_candidate)):
            raise ValueError('candidate contains non-generated changes; preserve it for review')
    else:
        remote = subprocess.check_output(['git', 'ls-remote', 'origin', f'refs/heads/{branch}'], text=True).split()
        lease = remote[0] if remote else ABSENT
        if remote:
            closed = api(f'pulls?state=closed&head=sourcebastion:{branch}&per_page=1')
            if not leftover_branch_is_refreshable(closed, lease, commits, files):
                raise ValueError('unowned or changed branch; preserve it for review')
    paths = subprocess.check_output(['git', 'diff', '--no-renames', '--name-only'], text=True).splitlines()
    automatic = not Path('.github/bundled-native-proposal.json').exists() and eligible(
        paths, git_read('HEAD'), lambda path: Path(path).read_text())
    with Path(os.environ['GITHUB_OUTPUT']).open('a') as stream:
        stream.write(f"branch={branch}\ndraft={'false' if automatic else 'always-true'}\nlease={lease}\n")


def main():
    automatic = False
    if (os.environ['GITHUB_EVENT_NAME'] == 'repository_dispatch'
            and os.environ['GITHUB_ACTOR'] == 'sourcebastion-bot[bot]'
            and os.environ['GITHUB_REF'] == 'refs/heads/main'):
        sha = os.environ['GITHUB_SHA']
        prs = json.loads(subprocess.check_output(['gh', 'api', f'repos/{REPOSITORY}/commits/{sha}/pulls']))
        for pr in prs:
            if not trusted_pr(pr, sha):
                continue
            # Compare the actual merged delta to its first parent, not a stale PR base.
            paths = subprocess.check_output(['git', 'diff', '--no-renames', '--name-only', f'{sha}^', sha], text=True).splitlines()
            automatic = {'VERSION', 'CHANGELOG.md'} <= set(paths) and eligible(paths, git_read(f'{sha}^'), git_read(sha))
            if automatic:
                break
    environment = 'scanner-maintenance' if automatic else 'release'
    with Path(os.environ['GITHUB_OUTPUT']).open('a') as stream:
        stream.write(f'environment={environment}\n')
    print(f'Release eligibility: {environment}; all image/security/runtime checks still required')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare', action='store_true')
    parser.add_argument('--install-push-guard', action='store_true')
    args = parser.parse_args()
    if args.prepare:
        prepare_candidate()
    elif args.install_push_guard:
        install_push_guard(os.environ['CANDIDATE_BRANCH'], os.environ['CANDIDATE_LEASE'],
                           Path(os.environ['RUNNER_TEMP']) / 'candidate-push-guard')
    else:
        main()
