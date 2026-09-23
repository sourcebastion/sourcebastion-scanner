#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 IMAGE COMMAND [ARG ...]" >&2
  exit 2
fi

image=$1
shift

# Match the GitHub-hosted runner identity so scanners can write generated
# dependency manifests and reports into the bind-mounted checkout.
exec docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -v "$PWD:/scan" \
  -w /scan \
  "$image" \
  "$@"
