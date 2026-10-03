#!/usr/bin/env bash
# Validate workflow expressions/action wiring with a reviewed actionlint binary.
set -euo pipefail
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
curl -sSfL https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz \
  -o "$temporary/actionlint.tar.gz"
echo "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8  $temporary/actionlint.tar.gz" | sha256sum -c -
tar -xzf "$temporary/actionlint.tar.gz" -C "$temporary" actionlint
# Existing disabled SARIF/writeback steps intentionally use a constant false.
"$temporary/actionlint" -shellcheck= -pyflakes= -ignore 'constant expression "false" in condition'
