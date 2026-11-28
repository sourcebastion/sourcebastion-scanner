# Scanner artifact verification

OpenGrep supplies SAST in the scanner image. The Linux amd64 and arm64 binaries
are pinned by version and SHA-256 in `.github/scanner-versions.json`. The
downloader checks the digest before installing an asset. The integrity workflow
checks the pinned binary version and validates the bundled GitLab config. The
native image checks verify the binary again and check its bundled notices.
For approved SAST rule sources, see [SAST rules and licensing](../README.md#sast-rules-and-licensing).

When updating OpenGrep, review the upstream release and the SHA-256 of both
assets. Update the binary pins and include the matching copyright, license, and
source information in [`third-party-notices/`](../third-party-notices/).

## Python and image dependencies

The image uses the `build` and `runtime` groups in `.github/python-locks/`.
CI verifies the locked wheels for all four Linux Python targets. Image builds
enforce exact versions and hashes, require wheels, run `pip check`, and build the
SourceBastion wheel offline from its reviewed source and locked build tools.

The former Semgrep pin, artifact evidence, and dependency locks are retained for
historical release verification. See the
[legacy verification procedure](https://github.com/sourcebastion/sourcebastion-scanner/blob/3ac7e8f1a6f8738c8e6fe407b128a9009820718b/docs/scanner-artifact-integrity.md)
for the previous images. The scheduled scanner workflow now refreshes the
retained runtime APK inputs.

## Bundled native library notices and sources

The runtime check compares the installed Python runtime's wheel-vendored
libraries against the reviewed entries in `.github/bundled-native-libraries.json`.
The retained libraries and notices for earlier releases are also recorded
there. Review exact library bytes, upstream source and build recipes, and
notices together when changing the runtime baseline.

`.github/native-source-pins.json` binds original upstream source/recipe archives,
the deterministic bundle and its OCI manifest. `Mirror bundled native sources`
checks all bytes before its separate main-only publisher receives package-write
authority; PR preparation cannot publish. A source change must pass preparation,
then publication and anonymous re-download on main before updating the image's
`third-party-notices/SOURCE-AVAILABILITY.md` directions. A digest mismatch stops
publication; do not replace a pin to conceal a mismatch. Retain source artifacts
for the scanner releases they accompany.

Native image CI and both staged-release hosted-scan jobs run
`scripts/assert-image-runtime.sh`, checking the OpenGrep binary, installed bundled bytes, and
retained texts against the reviewed manifests, including the source directions.
Image publication and host deployment are separate actions. See [M049](M049/README.md)
for distribution scope and the release acceptance record.
