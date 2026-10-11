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
# The proof drivers below leave read-only control directories inside $work on
# purpose, so a plain rm -rf cannot unlink their contents. Restore the owner
# write bit first, and never let cleanup change the verdict of the checks.
cleanup() {
  local status=$?
  chmod -R u+rwX "$work" 2>/dev/null || true
  rm -rf "$work" || true
  return "$status"
}
trap cleanup EXIT
mkdir -m 700 "$work/source" "$work/database" "$work/output"

# Advisory preparation never receives a checkout or any provider credentials.
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$work/database:/database" --entrypoint python "$image" \
  -c 'import os,runpy,sys; os.umask(0o077); sys.argv=["sourcebastion.grype_database","/database"]; runpy.run_module("sourcebastion.grype_database",run_name="__main__")'
database="$(readlink -f "$work/database/current")"

# Separate canonical SBOM/real-Grype evidence reuses this source-free generation.
# Fixed reviewed fixture only; no change to the released directory-scan route.
canonical_output="${SOURCEBASTION_NATIVE_GRYPE_PROOF_OUTPUT:-$work/canonical-output}"
mkdir -m 700 "$work/canonical-source" "$canonical_output"
python3 - "$root/evaluation/m046/real-grype-native-fixture-v3.json" "$work/canonical-source" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

fixture = json.loads(Path(sys.argv[1]).read_bytes())
root = Path(sys.argv[2])
for row in fixture['files']:
    relative = Path(row['path'])
    assert not relative.is_absolute() and '..' not in relative.parts
    raw = row['utf8'].encode()
    assert hashlib.sha256(raw).hexdigest() == row['sha256']
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('xb') as handle:
        handle.write(raw)
PY
docker run --rm --init --no-healthcheck --user "$(id -u):$(id -g)" \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --cpus 2 --memory 2g --memory-swap 2g --pids-limit 256 \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  -e PYTHONPATH= -e HOME=/tmp -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$root:/src:ro" -v "$work/canonical-source:/fixture:ro" \
  -v "$database:/advisories:ro" -v "$canonical_output:/out" \
  -w /src --entrypoint python "$image" scripts/verify-inventory-real-grype.py

# Upgrade parity uses the same verified advisory generation for both source
# heads. Baseline proof code runs with its own matching installed module map.
if [[ -n "${SOURCEBASTION_UPGRADE_BASE_IMAGE:-}" ]]; then
  : "${SOURCEBASTION_UPGRADE_BASE_CHECKOUT:?baseline checkout required}"
  baseline_output="$canonical_output/baseline"
  mkdir -m 700 "$baseline_output"
  docker run --rm --init --no-healthcheck --user "$(id -u):$(id -g)" \
    --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
    --cpus 2 --memory 2g --memory-swap 2g --pids-limit 256 \
    --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    -e PYTHONPATH= -e HOME=/tmp -e PYTHONDONTWRITEBYTECODE=1 \
    -v "$SOURCEBASTION_UPGRADE_BASE_CHECKOUT:/src:ro" -v "$work/canonical-source:/fixture:ro" \
    -v "$database:/advisories:ro" -v "$baseline_output:/out" \
    -w /src --entrypoint python "$SOURCEBASTION_UPGRADE_BASE_IMAGE" scripts/verify-inventory-real-grype.py
  baseline_snapshot="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["consumer"]["advisory_snapshot_sha256"])' "$baseline_output/receipt.json")"
  candidate_snapshot="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["consumer"]["advisory_snapshot_sha256"])' "$canonical_output/receipt.json")"
  python3 "$root/scripts/verify-inventory-upgrade.py" \
    --baseline "$root/inventory-base-oracle.json" --candidate "$root/inventory-source-expectations-native.json" \
    --baseline-findings "$baseline_output/grype.json" --candidate-findings "$canonical_output/grype.json" \
    --baseline-snapshot "$baseline_snapshot" --candidate-snapshot "$candidate_snapshot" \
    --output "$canonical_output/upgrade-with-findings.json"
fi

# Separate inactive fixed-controller evidence; expected generation facts are
# prepared by the trusted CI parent without project input or credentials.
# The actual controller includes runtime/status/hash/analysis in one150s ledger.
# Docker resource flags alone do not establish aggregate120CPU or host custody.
dependency_output="${SOURCEBASTION_NATIVE_DEPENDENCY_JOB_OUTPUT:-$work/dependency-output}"
mkdir -m 700 "$work/dependency-preparation" "$dependency_output"
python3 "$root/scripts/prepare-inventory-dependency-job.py" \
  "$database" "$work/dependency-preparation"
docker run --rm --init --no-healthcheck --user "$(id -u):$(id -g)" \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --cpus 2 --memory 2g --memory-swap 2g --pids-limit 256 \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  -e PYTHONPATH= -e HOME=/tmp -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$root:/src:ro" -v "$work/canonical-source:/fixture:ro" \
  -v "$database:/advisories:ro" -v "$work/dependency-preparation:/preparation:ro" \
  -v "$dependency_output:/out" -w /src --entrypoint python "$image" \
  scripts/verify-inventory-dependency-job.py

# Separate actual installed private entrypoint proof. The CI driver owns each
# fresh container, bounds external receipt capture and retains first failures.
# This finite fixture does not qualify production kernel/custody/admission.
entrypoint_output="${SOURCEBASTION_NATIVE_ENTRYPOINT_OUTPUT:-$work/entrypoint-output}"
mkdir -m 700 "$entrypoint_output"
for repeat in 1 2 3; do
  mkdir -m 700 "$entrypoint_output/repeat-$repeat"
  python3 "$root/scripts/run-inventory-entrypoint-proof.py" \
    --image "$image" --checkout "$root" --source "$work/canonical-source" \
    --advisories "$database" --preparation "$work/dependency-preparation" \
    --output "$entrypoint_output/repeat-$repeat"
done

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
import json
import os
import subprocess
import time
from unittest.mock import patch

from sourcebastion.config import ScannerSettings
from sourcebastion.external_scanners import GrypeScanner

# Observe the real subprocess boundary; delegate every command unchanged.
# Both cases reuse the same immutable advisory mount.
real_run = subprocess.run
for mode in ('environment', 'repository-with-deadline'):
    os.environ['SOURCEBASTION_SETUP_TIMEOUT_GRYPE'] = '90' if mode == 'environment' else '1'
    scanner = GrypeScanner()
    if mode == 'repository-with-deadline':
        scanner.configure_timeouts(ScannerSettings(setup_timeout=300))
        scanner.set_execution_deadline(time.monotonic() + 120)
    budgets = {}

    def observed_run(command, *args, **kwargs):
        if command == ['grype', '--version']:
            assert 0 < kwargs['timeout'] <= 30
            budgets['probe'] = kwargs['timeout']
        elif command == ['grype', 'db', 'status']:
            assert kwargs['env']['GRYPE_DB_VALIDATE_BY_HASH_ON_START'] == 'true'
            assert kwargs['env']['GRYPE_DB_VALIDATE_AGE'] == 'true'
            assert kwargs['env']['GRYPE_DB_AUTO_UPDATE'] == 'false'
            assert kwargs['env']['GRYPE_CHECK_FOR_APP_UPDATE'] == 'false'
            if mode == 'environment':
                assert kwargs['timeout'] == 90
            else:
                assert 1 < kwargs['timeout'] <= 120
            budgets['database_status'] = kwargs['timeout']
        else:
            assert command[:2] == ['grype', 'dir:/workspace'], command
            budgets['analysis'] = kwargs['timeout']
        return real_run(command, *args, **kwargs)

    with patch('sourcebastion.external_scanners.subprocess.run', observed_run):
        findings, raw_path = scanner.scan_with_raw_output('/workspace')
    try:
        assert any('requests' in str(finding.get('title', '')) for finding in findings), (
            'Python-only manifest scan lost dependency vulnerabilities'
        )
        assert set(budgets) == {'probe', 'database_status', 'analysis'}
        if mode == 'repository-with-deadline':
            assert 0 < budgets['analysis'] <= budgets['database_status']
        print(json.dumps({'proof': 'grype-setup-budget/1', 'mode': mode, 'budgets': budgets}))
    finally:
        os.unlink(raw_path)
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
