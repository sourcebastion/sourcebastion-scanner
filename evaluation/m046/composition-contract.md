# Composition feasibility contract v1

Status: S01 prototype and architecture input, not a selected production engine.
The executable spike proves a small joining boundary. S03 still owns complete
adapters and canonical composition across the promised formats.

## Ownership and identity

Direct static Python owns Python source declarations, includes, constraints,
supported manifests/locks and their located occurrences. A declared pin never
claims installation. The restricted pinned Syft profile owns its raw provider
IDs and observations for non-Python and installed metadata. Neither a shared
purl nor equal names/versions authorizes merging those authorities.

The prototype derives separate source-occurrence and provider-evidence SHA256
IDs from typed records and source hashes. Direct occurrence records retain
their root, locator, scope, version evidence and conditions. Provider IDs,
paths, raw metadata and versions survive separately. Two roots with an equal
purl remain two source occurrences; installed evidence of that same version
remains a third, separately typed record. These prototype IDs are not a new
production finding identity or cache contract.

Provider paths bind to regular files through the controller's `Source` reader.
It checks descriptors, metadata, budgets and final bytes. A path's directory
is an analysis scope, not a project or installed environment. Provider canonical
roots and installed environments remain null. Immutable outer input and job
custody remain necessary; this prototype does not supply physical fencing or
persistent cross-call custody.

## Minimal source-aware adapters

Installed Python feasibility admits only `.dist-info/METADATA` with the reviewed
`python` / `python-package` role and Core Metadata 2.1. Each mandatory header is
unique. Source name/version, raw provider fields and purl must agree; names and
versions must satisfy the pinned packaging validators. Other metadata versions
remain unadapted here. Activation/environment stay unknown. `Requires-Dist`
ranges remain metadata; this adapter does not resolve or invent their versions.
The required fields and identity syntax follow the
[Core Metadata specification](https://packaging.python.org/en/latest/specifications/core-metadata/).

A source `package.json` outside `node_modules` can establish declared application
metadata when its source name/version agree with the provider record. Duplicate
keys and nonfinite JSON refuse. This is not a canonical npm graph adapter or
proof of project ownership. Installed package metadata remains role-unassessed.
Versionless npm/Go metadata stays unselected with a null identity. Exact-looking
Go/POM version candidates stay declarations. Non-Python lock evidence remains
unadapted and cannot enter matching merely because a versioned purl exists.

Provider dependency direction and raw-ID endpoints survive. Shared evidence
paths retain analysis scopes. The prototype does not promote those observations
to canonical matching edges, infer a missing endpoint, lend an identity from
another record or erase ambiguous context. S03 source-aware lock adapters must
recover locators, selected versions, application roles, roots, scope and evidenced
edges from supported source data. Missing facts must remain explicit losses or
unsupported dispositions, rather than being filled from test expectations.

## Status, bounds and proof scope

The result always reports partial inventory and `full_contract_qualified=false`.
It retains the direct inventory's unsupported input dispositions and explicit
provider coverage/adapter losses. No standard export, Grype matching or cache
integration runs. Range-only, malformed, ambiguous and unsupported metadata
cannot become an empty successful inventory.

The spike reuses the bounded source reader, provider tree/record limits and
64 MiB complete-output encoder. The audit child has a 1 GiB address-space limit,
20 CPU seconds and a guarded 30-second wall deadline. The provider runs in the
existing synthetic namespace/trace harness. Those are finite diagnostic bounds;
they are not shared production cgroup measurements or a filesystem jail.

`composition_native.py` creates one synthetic collection with two equal Python
pins in distinct roots, installed pip metadata, npm application/lock evidence,
a versionless Go replacement and a declared Go minimum. It runs the provider
twice, then separately extracts and checks the composition. All source/binary/
code/tracer/preparation identities and raw outputs are retained. Strict trace
admission is a separate result; failures are never upgraded by semantic success.
Actual native AMD64/ARM64 CI is required for the published head.

## Delivery boundary

S01 requires a reviewed design, comparison, numerical ceilings and finite
composition/runtime/license feasibility. It does not require implementing all
production adapters before the S03 issue which depends on that decision.
The proposed architecture is direct canonical Python plus one restricted
evidence provider, source-aware canonical adapters and local CycloneDX to Grype.
Engine selection and budget freeze remain pending their concrete review.

S02 owns the maintained discovery/dispatch registry. S03 owns complete supported
source/installed adapters, typed composition and semantic regression acceptance.
S04 owns production export, Grype/finding/location/cache compatibility. S05 owns
designed coverage presentation, ingestion, access, retention, deletion and mixed
versions. S06 owns final image/native closure/notices/update gates. S07 owns the
verified release and normal 8 CPU / 12 GiB dev human and rollback acceptance.
M047 owns the SBOM browser. No milestone, deployment or recovery authority is
created by this prototype.
