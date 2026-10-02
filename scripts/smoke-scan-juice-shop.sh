#!/usr/bin/env bash
#
# Final image check: make the built image scan a real vulnerable application
# and prove each scanner actually produced findings.
#
# Everything else in this workflow tests the image at one remove.
# `verify-scanner-integration.py` checks each binary is on PATH with
# `shutil.which` and then patches `subprocess.run`, feeding fixture JSON
# through the parsers -- so it proves parsing, never execution. That gap is not
# theoretical: `which grype` passed while a real grype run failed, because the
# failure was in the `pip` call grype makes to materialise dependencies, and
# separately semgrep failed entire scans on any repository containing a file it
# could not fully parse. Both reached a release.
#
# So this runs the real thing over a corpus with real findings. Juice Shop is
# deliberately vulnerable across several ecosystems and is exactly the shape
# that broke semgrep -- a large JavaScript application carrying vendored and
# minified files.
#
# Pinned to a commit rather than tracking the branch: a release must not fail
# because an upstream repository changed this morning. Bump the pin
# deliberately.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 IMAGE" >&2
  exit 2
fi

image=$1
# sourcebastion/juice-shop, a fork the organization owns.
corpus_repo="sourcebastion/juice-shop"
corpus_sha="8fb217241af4f9970be17b621bb7ef51fa7891da"
#: Scanners this corpus genuinely exercises. kics and custom_php are absent
#: deliberately: Juice Shop carries no Terraform and no PHP, so asserting them
#: here would assert nothing and then fail the day it changed.
expected_scanners="semgrep gitleaks grype"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# A git checkout, not a tarball. gitleaks scans commits, so an exported tree
# with no `.git` yields zero secrets from it -- which is both unrepresentative
# (customers scan working trees) and a silent loss of coverage for an entire
# scanner. A depth-1 fetch is enough: the pinned commit's content is still a
# commit for gitleaks to read.
echo "Fetching ${corpus_repo} at ${corpus_sha:0:12}"
mkdir -p "$work/corpus"
git init -q "$work/corpus"
git -C "$work/corpus" remote add origin "https://github.com/${corpus_repo}.git"
git -C "$work/corpus" fetch -q --depth 1 origin "$corpus_sha"
git -C "$work/corpus" checkout -q FETCH_HEAD

mkdir -p "$work/corpus/scan-results"
# Readable by the container user, which is not this uid.
chmod -R a+rX "$work/corpus"
chmod 777 "$work/corpus/scan-results"

echo "Scanning with ${image}"
cd "$work/corpus"
"$root/scripts/run-scanner-container.sh" "$image" \
  scan . --severity all --output scan-results/report.json

python3 - "$work/corpus/scan-results/report.json" "$expected_scanners" <<'PYEOF'
import collections
import json
import sys

report_path, expected = sys.argv[1], sys.argv[2].split()
with open(report_path, encoding="utf-8") as handle:
    report = json.load(handle)

findings = report.get("vulnerabilities")
if findings is None:
    raise SystemExit(f"report has no 'vulnerabilities' key: {sorted(report)}")

counts = collections.Counter(finding.get("scanner") for finding in findings)
print(f"total findings: {len(findings)}")
for name, count in sorted(counts.items(), key=lambda item: -item[1]):
    print(f"  {name}: {count}")

# Liveness per scanner, not exact counts. A corpus's findings drift as it and
# the advisory data change, and a test that pins numbers gets disabled the
# first time it is wrong for an innocent reason. Zero findings from a scanner
# that should see this corpus is never innocent.
silent = [name for name in expected if not counts.get(name)]
if silent:
    raise SystemExit(
        f"these scanners produced no findings on a deliberately vulnerable "
        f"application: {silent}. Either the scanner did not run, or it failed "
        f"in a way the scan swallowed."
    )

if not findings:
    raise SystemExit("the scan produced an empty report")
print(f"all expected scanners reported findings: {expected}")
PYEOF
