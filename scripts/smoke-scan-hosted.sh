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
  -v "$work/database:/database" --entrypoint python "$image" \
  -m sourcebastion.grype_database /database
database="$(readlink -f "$work/database/current")"

cp "$root/tests/fixtures/scanners/deps/"*.json "$work/source/"
cp "$root/tests/fixtures/scanners/iac/main.tf.fixture" "$work/source/main.tf"
printf 'requests==2.19.1\n' > "$work/source/requirements.txt"
cat > "$work/source/app.py" <<'PY'
import subprocess


def execute(command):
    subprocess.call(command, shell=True)
PY
# Construct a fake token; alphabet sequences are in Gitleaks' global allowlist.
python3 - "$work/source/token.py" <<'PY'
import hashlib
from pathlib import Path
import sys

token = 'ghp_' + hashlib.sha256(b'sourcebastion-offline-test-fixture').hexdigest()[:36]
Path(sys.argv[1]).write_text(f'GITHUB_TOKEN="{token}"\n')
PY
git -C "$work/source" init -q
git -C "$work/source" add .
git -C "$work/source" -c user.name=Fixture -c user.email=fixture@example.invalid commit -qm fixture

# Exercise both execution modes with the same immutable inputs and advisory generation.
for scanner_workers in 1 3; do
mkdir -m 700 "$work/output/$scanner_workers"
echo "Hosted scanner component workers: $scanner_workers"
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -e "SOURCEBASTION_SCANNER_WORKERS=$scanner_workers" \
  -e SOURCEBASTION_SCAN_OFFLINE=1 -e GRYPE_DB_AUTO_UPDATE=false \
  -e GRYPE_CHECK_FOR_APP_UPDATE=false -e GRYPE_DB_CACHE_DIR=/advisories \
  --network none -v "$work/source:/workspace:ro" \
  -v "$database:/advisories:ro" -v "$work/output/$scanner_workers:/out" \
  -w /workspace "$image" scan . --severity all --output /out/vulnerabilities.json

python3 - "$work/output/$scanner_workers/vulnerabilities.json" <<'PY'
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
done

python3 - "$work/output/1/vulnerabilities.json" "$work/output/3/vulnerabilities.json" <<'PY'
from collections import Counter
import json
import sys

reports = [json.load(open(path))['vulnerabilities'] for path in sys.argv[1:]]
identities = [Counter(finding['finding_id'] for finding in report) for report in reports]
assert identities[0] == identities[1], 'parallel execution changed hosted finding identities'
print('Serial and parallel hosted scans preserve the complete finding identity multiset')
PY
test ! -e "$work/source/.grype-deps"
test ! -e "$work/source/node_modules"

# A Python-only checkout must also work: an npm lockfile must not short-circuit
# the wrapper and hide a forbidden pip install into the read-only checkout.
mkdir -m 700 "$work/python"
printf 'requests==2.19.1\n' > "$work/python/requirements.txt"
docker run --rm -i --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -e SOURCEBASTION_SCAN_OFFLINE=1 -e GRYPE_DB_AUTO_UPDATE=false \
  -e GRYPE_DB_CACHE_DIR=/advisories --network none \
  -v "$work/python:/workspace:ro" -v "$database:/advisories:ro" \
  --entrypoint python "$image" - <<'PY'
from sourcebastion.external_scanners import GrypeScanner

findings = GrypeScanner().scan('/workspace')
assert any('requests' in str(finding.get('title', '')) for finding in findings), (
    'Python-only manifest scan lost dependency vulnerabilities'
)
print('Python-only read-only checkout reported dependency vulnerabilities')
PY
test ! -e "$work/python/.grype-deps"

for max_age in 120h 1ns; do
  cache=/advisories
  if [[ "$max_age" == 120h ]]; then cache=/missing-database; fi
  docker run --rm -i --user "$(id -u):$(id -g)" -e HOME=/tmp \
    -e SOURCEBASTION_SCAN_OFFLINE=1 -e GRYPE_DB_AUTO_UPDATE=false \
    -e "GRYPE_DB_CACHE_DIR=$cache" -e "GRYPE_DB_MAX_ALLOWED_BUILT_AGE=$max_age" \
    --network none -v "$work/source:/workspace:ro" \
    -v "$database:/advisories:ro" --entrypoint python "$image" - <<'PY'
from sourcebastion.external_scanners import GrypeScanner, ScannerExecutionError

try:
    GrypeScanner().scan('/workspace')
except ScannerExecutionError as exc:
    assert exc.scanner == 'grype' and exc.code == 'execution_failed'
    print('Missing/stale advisory data refused without a clean report')
else:
    raise SystemExit('Invalid advisory database silently passed')
PY
done
