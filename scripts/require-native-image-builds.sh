#!/usr/bin/env bash
# The required check behind the native image proofs.
#
# Separate from the workflow so it is testable: this is the only thing standing
# between a merge and the jobs that exercise the installed image, and it must
# stay fail-closed. A skip is accepted only when the path classifier succeeded
# and explicitly reported the change as unable to affect the image. An
# unexplained skip, a cancelled or failed classifier, and a failed or cancelled
# build all refuse.
#
# Reads BUILD_RESULT, CHANGES_RESULT and IMAGE_AFFECTING from the environment.
set -euo pipefail

build="${BUILD_RESULT:-}"
changes="${CHANGES_RESULT:-}"
affecting="${IMAGE_AFFECTING:-}"

if [ "$build" = success ]; then
  echo "Both native image builds succeeded."
  exit 0
fi

if [ "$changes" = success ] && [ "$affecting" = false ] && [ "$build" = skipped ]; then
  echo "Documentation-only change; native image builds correctly skipped."
  exit 0
fi

echo "Native image builds did not succeed (build: ${build:-unset}," \
  "classifier: ${changes:-unset}, image_affecting: ${affecting:-unset})."
exit 1
