#!/usr/bin/env bash
#
# Real-execution check for the IaC component.
#
# Separate from the Juice Shop smoke scan because that corpus is a JavaScript
# application with no infrastructure code, so it cannot exercise KICS -- which
# is why `kics` is absent from its required scanners, and why KICS returning
# nothing for every repository went unnoticed through several releases.
#
# The defect it guards: the wrapper read `queryName`, `results` and `file`,
# while KICS emits `query_name`, `files` and `file_name`. Every existing
# fixture was hand-written in the shape the parser expected, so the unit tests
# agreed with the bug. Only running the real binary and reading its real
# output distinguishes the two.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 IMAGE" >&2
  exit 2
fi

image=$1
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The fixture is stored with a suffix so the repository's own scans do not
# treat it as live infrastructure; KICS needs the real extension.
cp "$root/tests/fixtures/scanners/iac/main.tf.fixture" "$work/main.tf"
chmod -R a+rX "$work"

echo "Running the IaC component in ${image}"
# The program is fed on stdin rather than through `python3 -c '...'`: the
# single-quoted shell form cannot contain single quotes, which forced escaped
# double quotes inside f-strings -- a syntax error on the image's Python 3.11.
docker run --rm -i --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$work:/scan:ro" --entrypoint python3 "$image" - <<'PYEOF'
import sys

from sourcebastion.external_scanners import KicsScanner

scanner = KicsScanner()
if not scanner.is_installed():
    sys.exit("kics is not installed in this image")

findings = scanner.scan("/scan")
print("kics findings: {}".format(len(findings)))
for finding in findings:
    print("  {}: {} ({}:{})".format(
        finding["severity"], finding["title"], finding["file"], finding["line"]
    ))

if not findings:
    sys.exit(
        "kics reported no findings on a fixture with an unrestricted security "
        "group. The binary runs, so this is the wrapper discarding real output."
    )

titles = {finding["title"] for finding in findings}
if not any("Ingress" in title or "Port" in title for title in titles):
    sys.exit("expected an open-ingress finding, got: {}".format(sorted(titles)))

if any(finding["file"] == "unknown" for finding in findings):
    sys.exit("a finding has no file path, so the occurrence keys are misread")

print("IaC component reports real findings with real locations")
PYEOF
