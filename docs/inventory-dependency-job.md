# Inactive fixed-consumer dependency job

`dependency_job.run_dependency` combines direct source composition, immutable
canonical retention, CycloneDX export, fixed Grype execution, and exact-ID
recovery. It is a private library with no CLI or customer route yet. A caller
must create the Source and PipelineBudget at dependency job admission, clamped
to the existing outer deadline and the 150-second limit. This function never
creates another ledger or timeout allowance. Runtime hashing, version/status,
analysis, recovery, serialization and final validation consume that same job.
There is no source-free 330-second proof admission phase in this implementation.

Only trusted controller code constructs `RuntimeSpec`. It binds the official
prepared Grype 0.119.0 executable digest/size and the exact maintained advisory
generation's file paths, digests, sizes, schema and build identity. It is not
deserialized from a project configuration. Executable and advisory paths are
fixed controller constants. The advisory tree admits at most32 files,
32 directories, depth8 and4GiB; its snapshot is at most2MiB. These are runtime
preparation input bounds, separate from project parsing and artifact retention.

Runtime admission holds the binary and every advisory file/directory open,
refuses symlinks, nonregular files, extra entries, hardlinks and group/other
writable files or directories, and hashes all bytes using the shared callback.
It checks visible and held identities throughout and rehashes the full closure
at finalization. Grype executes the admitted native ELF through its held FD,
passed explicitly to the child. Runtime descriptors stay open through receipt
preparation and final source/artifact checks, with a final runtime identity
check after artifact validation. These finite checks do not fence another
administrator with the same identity or establish mount origin independence.

The parent must independently bind the release, parser/module closure, source
and output custody, immutable read-only runtime/advisory/source mounts and the
actual dedicated dependency container before admitting this library's output.
It must enforce2CPU/2GiB/noSwap/PID256, aggregate120CPU seconds and the shared
wall deadline, and drain/reap/remove the whole job on every exit, including
controller death. This library does not implement or attest that host boundary.
Missing parent evidence must refuse customer acceptance. A Python callback or
child JSON cannot provide that authority.

The consumer receives a fixed explicit configuration, minimal private
environment/cwd/home, stdin disabled and only an explicit generated SBOM path.
The fixed environment sets `GOMAXPROCS=2` for every version/status/analysis
invocation. This Go scheduling policy is separate from the parent CPU quota
and aggregate CPU-time enforcement; a parent environment cannot override it.
Network, update, install, resolution and project execution are not requested;
the parent must enforce actual offline operation. Version and status streams
reserve at most64KiB each. Analysis stdout uses the configured diagnostic-file
ceiling and stderr at most64KiB. Every full stream ceiling and the64KiB control
record count toward the same nonrefundable256MiB artifact allowance. Config,
inventory, SBOM, raw reports and recovered context remain exclusive held files.
`consumer-config.json` retains the exact explicit environment/cwd and YAML hash
used to calculate the consumer configuration identity, including ephemeral
private paths. Parent readers can reconstruct that hash after scratch cleanup.

The version/status commands must match preparation facts. The separately bound
snapshot must agree with the actual valid database status.
Both actual status and the raw analysis database path must exactly identify
the fixed bound `ADVISORIES/6/vulnerability.db` file. Analysis exit code,
complete raw output, matching structure, consumer/database identity and exact
occurrence recovery are distinct checks. Exit zero alone never admits a scan.
Nonzero analysis retains numeric exit and diagnostic bytes; later failure
preserves earlier canonical inventory/export facts. Unresolved and unsupported
inventory stays partial. Canonical StageStates are never rewritten to encode
later consumer execution or failure.

The bounded versioned execution receipt contains child artifact facts only:
source/config/environment/producer/consumer identities, canonical inventory
state, stage outcomes, raw process exit/lifecycle, recovery identity,
nonrefundable reservations, semantic usage and artifact hashes/sizes. Its
`kernel_admission` is always `not_observed`. The `finalized` return flag means
finalized child facts; it is never a parent-accepted vulnerability scan.
Public reason strings omit exception text, raw stderr and customer paths.

Unit evidence uses tiny prepared native-header fixtures and explicit
mock capture documents. They are not actual Grype/advisory execution, full
kernel or lifecycle evidence, installed/native qualification, release
packaging, platform negotiated transport or M046 completion. The existing
legacy scanner and M036 inner protocol remain unchanged. The separate
`scripts/verify-inventory-dependency-job.py` requires installed native execution
of a source-authored fixture with retained configuration and exact recovery;
its current-head CI artifacts need independent review. Fixed CLI/host launch,
kernel enforcement and release/development acceptance remain subsequent gates.
