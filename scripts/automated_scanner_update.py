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


def candidate_branch(prs, commits):
    candidates = [pr for pr in prs if pr['head']['ref'].startswith(PREFIX)]
    if len(candidates) > 1:
        raise ValueError('multiple bot candidates require reconciliation')
    if not candidates:
        return PREFIX + 'update'
    pr = candidates[0]
    history = commits(pr)
    if (pr['user']['login'] != 'sourcebastion-bot[bot]'
            or pr['head']['repo']['full_name'] != REPOSITORY
            or not history or len(history) >= 100
            or any((row.get('author') or {}).get('login') != 'sourcebastion-bot[bot]' for row in history)):
        raise ValueError('candidate has human or unknown work; preserve it for review')
    return pr['head']['ref']


def prepare_candidate():
    if os.environ['APP_SLUG'] != 'sourcebastion-bot':
        raise ValueError('expected existing sourcebastion-bot App')
    def api(path):
        return json.loads(subprocess.check_output(['gh', 'api', f'repos/{REPOSITORY}/{path}']))
    prs = api('pulls?state=open&base=main&per_page=100')
    if len(prs) >= 100:
        raise ValueError('candidate list truncated; preserve existing work for review')
    branch = candidate_branch(prs, lambda pr: api(f"pulls/{pr['number']}/commits?per_page=100"))
    if not any(pr['head']['ref'] == branch for pr in prs):
        remote = subprocess.check_output(['git', 'ls-remote', 'origin', f'refs/heads/{branch}'], text=True).split()
        if remote:
            closed = api(f'pulls?state=closed&head=sourcebastion:{branch}&per_page=1')
            if (not closed or not closed[0]['merged_at'] or closed[0]['head']['sha'] != remote[0]
                    or closed[0]['user']['login'] != 'sourcebastion-bot[bot]'):
                raise ValueError('unowned or manually closed branch; preserve it for review')
    for pr in prs:
        if pr['head']['ref'] == branch:
            files = api(f"pulls/{pr['number']}/files?per_page=100")
            if len(files) >= 100 or not all(allowed(row['filename']) or row['filename'] == '.github/bundled-native-proposal.json' for row in files):
                raise ValueError('candidate contains non-generated changes; preserve it for review')
    paths = subprocess.check_output(['git', 'diff', '--no-renames', '--name-only'], text=True).splitlines()
    automatic = not Path('.github/bundled-native-proposal.json').exists() and eligible(
        paths, git_read('HEAD'), lambda path: Path(path).read_text())
    with Path(os.environ['GITHUB_OUTPUT']).open('a') as stream:
        stream.write(f"branch={branch}\ndraft={'false' if automatic else 'always-true'}\n")


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
    if parser.parse_args().prepare:
        prepare_candidate()
    else:
        main()
