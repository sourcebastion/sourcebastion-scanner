#!/usr/bin/env bash
# Real hosted-worker boundary: no network, read-only source/advisories, private output.
set -euo pipefail
if [[ $# -ne 1 ]]; then
  echo "usage: $0 IMAGE" >&2
  exit 2
fi
image=$1
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -m 700 "$work/source" "$work/database" "$work/output"

# Advisory preparation never receives a checkout or any provider credentials.
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -e GRYPE_DB_CACHE_DIR=/database -e GRYPE_CHECK_FOR_APP_UPDATE=false \
  -v "$work/database:/database" --entrypoint grype "$image" db update

cp "$root/tests/fixtures/scanners/deps/"*.json "$work/source/"
cp "$root/tests/fixtures/scanners/iac/main.tf.fixture" "$work/source/main.tf"
printf 'requests==2.19.1\n' > "$work/source/requirements.txt"
cat > "$work/source/app.py" <<'PY'
import subprocess


def execute(command):
    subprocess.call(command, shell=True)
PY
# Construct an intentionally fake token without checking a token into this repo.
printf '%s%s\n' 'GITHUB_TOKEN="ghp_' 'abcdefghijklmnopqrstuvwxyz1234567890"' > "$work/source/token.py"
git -C "$work/source" init -q
git -C "$work/source" add .
git -C "$work/source" -c user.name=Fixture -c user.email=fixture@example.invalid commit -qm fixture

docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -e SOURCEBASTION_SCAN_OFFLINE=1 -e GRYPE_DB_AUTO_UPDATE=false \
  -e GRYPE_CHECK_FOR_APP_UPDATE=false -e GRYPE_DB_CACHE_DIR=/advisories \
  --network none -v "$work/source:/workspace:ro" \
  -v "$work/database:/advisories:ro" -v "$work/output:/out" \
  -w /workspace "$image" scan . --severity all --output /out/vulnerabilities.json

python3 - "$work/output/vulnerabilities.json" <<'PY'
import collections
import json
import sys

report = json.load(open(sys.argv[1]))
findings = report['vulnerabilities']
counts = collections.Counter(finding.get('scanner') for finding in findings)
missing = {'semgrep', 'gitleaks', 'grype', 'kics'} - {key for key, value in counts.items() if value}
assert not missing, f'hosted scan silently lost components: {missing}; counts={counts}'
dependencies = [finding for finding in findings if finding.get('scanner') == 'grype']
for package in ('requests', 'vm2'):
    assert any(package in str(finding.get('title', '')) for finding in dependencies), (
        f'{package} vulnerabilities missing from read-only manifest scan'
    )
print(f'Offline hosted scan reported findings from all four components: {dict(counts)}')
PY
test ! -e "$work/source/.grype-deps"
test ! -e "$work/source/node_modules"
