#!/usr/bin/env bash
#
# Assert that a built image reports the version being released.
#
# Every release through v1.7.34 published images whose `--version` said
# `0.1.0`, because the number lived in a setup.py literal instead of being
# derived from VERSION. Nothing noticed, because nothing asked the image.
#
# This asks the image. It is the only check here that tests the artifact that
# actually ships rather than the source it was built from, so it is the one
# that catches a packaging mistake that survives every unit test.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 IMAGE" >&2
  exit 2
fi

image=$1
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
expected="$(tr -d '[:space:]' < "$root/VERSION")"

if [[ -z "$expected" ]]; then
  echo "::error::VERSION is empty; cannot verify ${image}" >&2
  exit 1
fi

# `--version` prints "sourcebastion, version X.Y.Z". Take the last field so a
# change to the program name does not break the check.
reported="$(docker run --rm --entrypoint sourcebastion "$image" --version | awk 'NF{print $NF}' | tail -1)"

if [[ "$reported" != "$expected" ]]; then
  echo "::error::${image} reports version '${reported}' but VERSION declares '${expected}'" >&2
  exit 1
fi

echo "${image} reports version ${reported}"
