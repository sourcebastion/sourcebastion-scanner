# Static candidate runtime and image-cost experiment

The shipping image at release v1.7.38 is Alpine/musl, while the first Syft library
experiment deliberately builds with CGO enabled in a glibc evaluator. Its ELF
interpreter requires glibc; it is not a drop-in production payload. Syft 1.54.0's
upstream release configuration uses CGO_ENABLED=0, and this candidate registers
the pure-Go modernc SQLite driver required by the RPM/Nix catalogers. A separate
static build must be tested rather than assuming libc compatibility.

The runtime experiment will retain the existing glibc preparation as its default
and add an explicit static profile. Both profiles pin the same Go toolchain,
module graph and source identity. Static preparation must run the Go/frontend
contracts, record build information and prove native ELF architecture with no
PT_INTERP or PT_DYNAMIC entries. Changing source or executable identity refuses
evaluation. Local Python 3.13 diagnostic results are supporting evidence only.

The actual current release workflow publishes one standard image; historical
slim/micro targets are no longer built by this source. Report that fact rather
than inventing contemporary measurements for retired targets. Freeze the released
v1.7.38 multi-architecture image by digest, retain its registry manifests/configs,
verify architecture and version/Python labels, and verify published provenance
separately. Tag resolution and checksum comparison are not signature acceptance.

Trusted image preparation may download the two hash-pinned pure Python wheels,
create a dedicated venv with the image's Python and install them without project
sources. The runtime overlay contains only that venv, the static candidate and
the trusted frontend module tree. The scanned project is never an install/build
context. Python -I must use the venv interpreter, not PYTHONPATH or a resolved base
interpreter. All copied files and prepared runtime identities need retained hashes.

The initial payload's ELF interpreter requires glibc. An actual in-image negative
ABI proof remains separate; local ELF inspection alone does not establish that
execution result. On native AMD64 and ARM64 run the static candidate against the fixed
synthetic corpus in the prepared image with networking disabled, read-only root
and source, no capabilities, no-new-privileges, a fresh PID namespace, bounded
temporary space, a deadline and forced exact-container cleanup. Compare the same
40 admitted rich contracts and canonical occurrence/graph projection as outside
the image. Preserve unsupported inputs as partial. Test the actual exported image,
not a host interpreter or mounted host venv.

This initial runtime proof establishes ABI, pinned Python dependency availability,
offline enforcement, semantic agreement and image cost. Network denial alone does
not prove zero attempted sockets. It does not claim traced process/file behavior,
combined extension resource acceptance, a production jail or a frozen budget.
The separate full-candidate resource/cancellation/output tranche must enforce the
128 MiB + 4096-byte evaluation wrapper honestly, without raising diagnostic or
legacy capture bounds. Actual dev worker 8 CPU/12 GiB human acceptance remains open.

Export an OCI layout with gzip layers. Verify every layer digest/size, parent
manifest and exact baseline layer prefix. Calculate actual added compressed layer
bytes per architecture; a compressed executable estimate alone is insufficient.
Record full runtime and source/compiler identities, module licenses and maintained
dependency upgrade ownership before architecture/budget selection. Neither a green
runtime job nor an image within the proposed 250 MiB delta closes S01/S06/M046.

The implemented initial runner uses the existing cgroup controller with an
explicit immutable runtime-image exception for this experiment only. The trusted
controller starts as root with its existing minimal capabilities, then drops the
candidate to UID/GID65534 and no capabilities. Every finite fixture has a fresh
container/tmp/cache, source mounts read-only, network disabled and the existing
2CPU/2GiB/120CPU/150wall/64MiB raw bounds. That narrower raw bound honestly limits
this proof; it does not accept the full wrapper's larger worst case. The dedicated
identity probe has its own 20-second alarm, automatic removal and explicit forced
cleanup of its pre-recorded unique container name on host timeout. Inherited
health checks are disabled for both identity and measured runtime routes.

Preparation creates a venv without bundled pip; the released base pip installs
only the two already hash-pinned wheels offline with no dependencies/compilation.
The exported image preserves the baseline user/entrypoint/command/working directory.
The native runner verifies the actual venv Python3.14.8, isolated mode, complete
copied frontend and installed wheel-code hashes before any synthetic source scan.
An isolated host audit checks each retained result under 1GiB/20CPU/30wall limits;
source/binary/image-pin changes or any infrastructure/cleanup uncertainty abort
further attempts with durable plan/started/completed/not-started accounting.

OCI exports are retained separately with an explicit 2GiB artifact ceiling;
they never enter the unchanged 64MiB/file,1GiB raw/source archive. The validator
hashes bounded archive blobs without extracting paths/layers, checks referenced
descriptors, loaded configuration/diffIDs/native architecture and the exact
compressed baseline layer prefix. A separate isolated audit streams gzip layers
without extracting paths, verifies every uncompressed hash against the loaded
runtime diff IDs, and enforces 4GiB total expanded bytes,1GiB address space,
120CPU/150wall seconds (plus its120-second cooperative deadline). It does not
verify signatures. Build-context and actual payload hashes bind
the trusted experiment; published provenance and license acceptance remain open.
Historical PR101 trace completeness was withdrawn after undecoded shutdown records
were found. This runtime tranche neither repairs nor accepts that capture gate.
Docker/Buildx versions, builder inspection and actual BuildKit image IDs/repository
digests are retained. The action pin does not itself freeze Buildx/BuildKit;
publisher provenance and an accepted immutable build-tool policy remain pending.
