# Private fixed-path inventory entrypoint

`python -m sourcebastion.inventory_entrypoint` is a private child boundary.
The public scanner CLI and hosted routes do not invoke it. It accepts no path
or executable arguments. Its fixed mounts are `/source`, `/out`, `/advisories`
and `/control/job.json`; the optional Go parser path is fixed to
`/usr/local/bin/sourcebastion-go-source`. Packaging that helper remains a
separate release prerequisite; null helper identity preserves explicit
unsupported Go coverage instead of running customer tooling.

The exact controller-only record fields are `schema_version` (exactly
`sourcebastion.inventory-control/1`), `deadline_monotonic`, `source_sha256`,
`producer`, `discovery`, `environment`, `runtime`, and `go_sha256` (nullable).
Discovery has the five exact `DiscoveryConfig` fields, with mappings/ignores
as JSON arrays. Environment and Producer retain their canonical schemas;
producer registry/config identity must agree with the current registry and
actual discovery policy. Runtime has the six exact `RuntimeSpec` fields, with
advisory files as triples of relative path, digest and size. It cannot select
the Grype executable or advisory root. Source/Producer/runtime identities are
parent assertions, never an execution or custody attestation made by this JSON.

Capture monotonic entry time before heavier imports and parsing. The effective
absolute deadline is the smaller of parent `deadline_monotonic` and entry time
plus150 seconds. Apply the parent clamp before typed imports; no later stage
resets the allowance. Host and child must use the independently verified same
monotonic time namespace. Parent enforcement must cover interpreter/container
startup, blocked I/O, process descendants and controller death; this Python
callback does not implement those controls.

Hold the no-follow `/control` directory and descriptor-relative `job.json`
descriptors throughout the call. Require a regular, singly linked, read-only
file with the same owner as the nonwritable directory (root or effective user),
at most64KiB. FIFO opens are nonblocking and refused before reading. Bound
predecode nesting to16 and integer conversion to64 digits, reject duplicates,
invalid UTF-8/scalars and nonfinite numbers. Recheck visible and held metadata
plus exact content through finalization, including failure exits. These checks
do not fence a same-UID administrator or prove independent mount origin.

Use the existing Source, one PipelineBudget, fresh owner-only ArtifactStore
and `run_dependency` without another stage machine. Refuse a nonempty output
directory without removing evidence. Preserve failed library artifacts and
receipt. Keep Source and ArtifactStore descriptors open through the final
control-content validation on every exit. Before returning finalized facts,
revalidate cached source bytes and stored artifact bytes, then recheck control
metadata and cancellation/deadline. This finite validation is not persistent
race fencing; independently immutable parent mounts remain required.
A final control/cancellation/deadline uncertainty refuses delivery of
that receipt, retaining available private files for independent parent review.

Stdout is the existing bounded child receipt, at most64KiB, without a wrapper
that claims new authority. Exit0 means finalized child facts, exit2 means a
returned failed library receipt, and exit3 is a fixed bounded entrypoint refusal.
Signals request cancellation through the existing library Event. Parent must
drain/cap stdout; blocked or incomplete delivery is not acceptance. No overwrite,
cleanup, recovery adoption or findings publication is performed here.

The module lives outside `inventory/`. The existing96-file inventory proof map
therefore does not include this entrypoint. The parent must separately bind
the actual entrypoint and complete installed release/module closure, immutable
image and mounts, admitted source/record, plan and negotiated capability, actual
kernel2CPU/2GiB/noSwap/PID256/aggregate120CPU/wall limits, network-attempt and
all-descendant cleanup evidence. Missing parent evidence refuses hosted result
acceptance. Unit mocks are not a native entrypoint, kernel or release proof.
