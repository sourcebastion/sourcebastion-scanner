# Scanner image

SourceBastion ships one complete scanner image for Linux AMD64 and ARM64.
Docker selects the matching architecture from the same tag. Gitleaks, Grype,
KICS, Semgrep and the custom rules are included; pip and npm support project
dependency discovery.

The Dockerfile uses the smallest previous variant, micro, as its template:
Alpine and a copied virtual environment. Build tools, wheel archives, download
utilities and the source checkout stay in temporary stages. The final image
runs as `sourcebastion` with writable `/scan` and `/home/sourcebastion/.cache`.
CI reports the uncompressed image size for both architectures.
The inventory maintenance gate also verifies installed runtime pins, compares
source-authored upgrade expectations, measures fresh cgroup workloads and
enforces added compressed OCI layers. See the
[M046 maintenance runbook](docs/M046-maintenance-runbook.md) for the separate
release, distribution-closure and rollback requirements.

```bash
docker pull ghcr.io/sourcebastion/sourcebastion-scanner:latest
scripts/run-scanner-container.sh ghcr.io/sourcebastion/sourcebastion-scanner:latest scan .
```

The runner script maps the host UID/GID so reports and generated dependency
files can be written into a host checkout. Running the container directly
uses its default `sourcebastion` user; bind mounts must allow that user to write.

## Local build

```bash
images/build-docker.sh
# Equivalent native build, with the reviewed version as a build input:
docker build -f images/Dockerfile --build-arg PYTHON_VERSION="$(cat PYTHON_VERSION)" -t sourcebastion:local .
```

`PYTHON_VERSION` pins an exact patch release. Builder and runtime use the same
Python base, and runtime CI verifies that the interpreter matches the pin.
The locks require this exact version; changing the build argument alone fails.

## Release preparation

Dispatch **Prepare reviewed release** with the next scanner version, release
notes, and `python_version=latest` (the default), or an exact Python version.
It selects the newest compatible stable Python available in the official
Alpine image metadata, verifies the Semgrep publisher and every target wheel,
refreshes the dependency locks, and opens a release PR. It never merges or
publishes. Both native image builds and the normal release approval remain
required. The release build accepts `python_version` as an input and requires
it to match the reviewed source pin.

The previous `slim`, `micro`, `thin` and `semgrep` tags are retired. Existing
historical images remain available; new releases publish the complete scanner
as `vVERSION`, the full source SHA, and `latest`.
