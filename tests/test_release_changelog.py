"""Only the released version belongs in published release notes."""

import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/release-changelog.py'
spec = importlib.util.spec_from_file_location('release_changelog', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

CHANGELOG = '''## Unreleased

Future change

## [1.2.3](https://example.com/compare) (2026-09-29)

### Fixes

* Preserve compatibility

## [1.2.2](https://example.com/old)

Old change
'''


def test_extracts_exact_version_and_preserves_markdown():
    entry = module.release_entry(CHANGELOG, 'v1.2.3')
    assert entry.startswith('## [1.2.3](')
    assert '### Fixes\n\n* Preserve compatibility' in entry
    assert 'Future change' not in entry
    assert 'Old change' not in entry


@pytest.mark.parametrize('content', [CHANGELOG, '## 1.2.30\n\nNot this version'])
def test_missing_version_is_not_replaced_with_unreleased(content):
    with pytest.raises(ValueError):
        module.release_entry(content, '1.2.4')


@pytest.mark.parametrize('content', ['## 1.2.3\n\n', CHANGELOG + '\n## 1.2.3\n\nDuplicate'])
def test_empty_or_duplicate_entry_blocks_release(content):
    with pytest.raises(ValueError):
        module.release_entry(content, '1.2.3')


def test_notes_keep_github_summary_and_do_not_duplicate_changelog():
    entry = module.release_entry(CHANGELOG, '1.2.3')
    notes = "## What's Changed\n* PR #10\n\n## Security Scan\nResults"
    rendered = module.render_notes(entry, notes)
    assert rendered.endswith(notes + '\n')
    assert rendered.index('Preserve compatibility') < rendered.index("What's Changed")
    assert module.render_notes(entry, rendered) == rendered


def test_cli_reads_real_changelog():
    version = (ROOT / 'VERSION').read_text().strip()
    result = subprocess.run([sys.executable, str(SCRIPT), '--version', version],
                            cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert f'## [{version}]' in result.stdout
    assert '## Unreleased' not in result.stdout


def test_release_checks_changelog_before_tagging_and_publishes_it():
    workflow = yaml.load((ROOT / '.github/workflows/release.yml').read_text(), Loader=yaml.BaseLoader)
    steps = workflow['jobs']['prepare-release']['steps']
    names = [step['name'] for step in steps]
    assert names.index('Validate versioned changelog entry') < names.index('Create the draft release and immutable tag')
    publish = workflow['jobs']['update-github-release']['steps']
    assert publish[0]['with']['ref'] == '${{ needs.prepare-release.outputs.release_sha }}'
    script = publish[1]['run']
    assert '--notes-file /tmp/existing_notes.md > /tmp/release_notes.md' in script
    assert script.index('scripts/release-changelog.py') < script.index('gh release edit')
