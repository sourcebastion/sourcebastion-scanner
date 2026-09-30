"""Render one reviewed changelog entry into GitHub release notes."""

import argparse
from pathlib import Path
import re


START = '<!-- sourcebastion-changelog:start -->'
END = '<!-- sourcebastion-changelog:end -->'


def release_entry(changelog: str, version: str) -> str:
    version = version.removeprefix('v')
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('expected an exact release version')
    headings = list(re.finditer(r'^##[ \t]+(.+)$', changelog, re.MULTILINE))
    entries = []
    for index, heading in enumerate(headings):
        title = heading.group(1)
        if not re.match(r'(?:\[v?' + re.escape(version) + r'\]|v?'
                        + re.escape(version) + r'(?=\s|$))', title):
            continue
        end = headings[index + 1].start() if index + 1 < len(headings) else len(changelog)
        body = changelog[heading.end():end].strip()
        if not body:
            raise ValueError(f'changelog entry for {version} is empty')
        entries.append(changelog[heading.start():end].strip())
    if len(entries) != 1:
        raise ValueError(f'expected exactly one changelog entry for {version}')
    return entries[0]


def render_notes(entry: str, notes: str) -> str:
    # Resuming a draft must not duplicate the managed changelog section.
    notes = re.sub(re.escape(START) + r'.*?' + re.escape(END), '', notes, flags=re.DOTALL).strip()
    return f'{START}\n{entry}\n{END}\n\n{notes}\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--changelog', default='CHANGELOG.md')
    parser.add_argument('--notes-file')
    args = parser.parse_args()
    try:
        entry = release_entry(Path(args.changelog).read_text(encoding='utf-8'), args.version)
        if args.notes_file:
            print(render_notes(entry, Path(args.notes_file).read_text(encoding='utf-8')), end='')
        else:
            print(entry)
    except (OSError, ValueError) as exc:
        parser.exit(1, f'release changelog: {exc}\n')


if __name__ == '__main__':
    main()
