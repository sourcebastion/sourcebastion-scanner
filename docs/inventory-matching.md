# Canonical matching source recovery

`inventory.matching.recover` takes the revalidated canonical Inventory, the
exact locally generated CycloneDX Artifact and a controller-admitted Grype
JSON report. It re-exports the inventory to verify the complete artifact and
receipt rather than accepting caller-supplied hashes alone. Unknown IDs,
contradictory ecosystem/name/version/purl, malformed JSON, duplicate keys,
nonfinite values, invalid consumer/database identity and exceeded bounds refuse
atomically. It does not join equal purls, guess range versions or infer runtime
activation from CycloneDX's default scope.

Original output bytes and vulnerability metadata stay untouched. Each match
ordinal binds an exact canonical occurrence ID and normalized match digest.
Unique canonical occurrence contexts are retained separately, bounded by the
diagnostic byte limit; repeated advisories do not duplicate large source
contexts. Recovery identity includes canonical/export/output identities and
the controller's binary, config and immutable advisory snapshot identities.
Successful recovery does not mutate the original inventory stage states or
promote partial inventory coverage. Refusal preserves inventory and SBOM.

This is an internal report-admission and source-recovery function. It does not
execute Grype, authenticate JSON as genuine Grype output, verify controller
assertions, establish successful process exit, or prove source/binary/config/DB
custody. The execution controller must admit a successful complete explicit
SBOM scan under the shared deadline, semantic ledger and kernel resource,
network, source-isolation and cancellation boundary before calling it. The
database report's built/schema fields are consistency checks, not digest or
freshness authentication. Public scanner routing is unchanged in this slice.

Tests exercise source separation, original finding preservation, tampering,
invalid outputs and remaining budgets. Native installed probes use explicitly
synthetic reports and qualify source-recovery guards only. Separate actual
Grype/frozen advisory diagnostics, AMD64/ARM64 execution, rich corpus and
whole-pipeline acceptance remain required before S04 closure.
