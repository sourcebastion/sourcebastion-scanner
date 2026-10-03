#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_version="$(python3 "$root/scripts/python_version.py" current --requested "${PYTHON_VERSION:-}")"
case "$(uname -m)" in
  x86_64) native_arch=amd64 ;;
  aarch64|arm64) native_arch=arm64 ;;
  *) echo "Unsupported architecture" >&2; exit 1 ;;
esac
docker buildx build --load --platform "linux/$native_arch" \
  --build-arg "PYTHON_VERSION=$python_version" \
  --file "$root/images/Dockerfile" --tag sourcebastion:local "$root"
docker image inspect sourcebastion:local --format '{{json .}}' > /tmp/sourcebastion-image-inspect.json
python3 "$root/scripts/report_image_size.py" /tmp/sourcebastion-image-inspect.json "$native_arch"
"$root/scripts/assert-image-version.sh" sourcebastion:local
"$root/scripts/assert-image-runtime.sh" sourcebastion:local
