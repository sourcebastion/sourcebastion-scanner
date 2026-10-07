# Static pnpm source inventory

The canonical source composer admits registry pnpm lock format `9.0` through
existing descriptor-bound discovery. It reads every document, including the
separate environment/config and project documents. It never invokes pnpm,
loads project hooks, installs packages, fetches registries or chooses this
worker's platform. YAML is data only: aliases, anchors, tags, merge keys,
duplicate keys and complex map keys are refused before consumption. The
existing source cap, deadline and shared semantic ledger bound parsing;
32 documents, depth 32 and two million YAML nodes are additional ceilings.

Package-table observations and snapshot contexts retain different located
identities. Snapshot dependencies bind only their exact source-selected key
within the same document; equal package names, versions and purls do not join
peer contexts. A missing/refused snapshot cannot fall back to another version
or peer variant. Source-selected package versions use the existing pinned npm
semver grammar. Registry SRI values retain their declared digest type, and
registry URI identities are hashed. These are source assertions, not verified
artifact downloads. Missing/empty resolution metadata remains a partial fragment,
even when the package key independently observes name/version. Registry
resolution requires integrity; tarball resolution requires a tarball URI.
Unsupported dependency protocols retain fixed diagnostics
and source hashes without exposing credential-bearing expressions.

Each explicit importer receives a separate analysis scope. Runtime,
development, optional, configuration/build and package-manager/tooling selectors
remain separate; an optional edge preserves optional scope. Reachability and
scope propagation use only evidenced source edges. Observations outside these
closures keep an unowned scope; closure over another observed package creates
a separate occurrence in that scope. Importer paths do not establish an
application identity: roots stay nullable and no sibling manifest or folder
name assigns ownership. Activation stays unknown and graph fidelity partial;
source selection never establishes an installed environment. Other lock
versions, aliases/workspace/patch protocols and unsupported selection controls
remain explicit partial/unsupported coverage. This adapter does not interpret
peer activation or execute manager configuration. A proven package observation
can survive a separate unsupported row; global source/budget uncertainty clears
all consumable Python/npm/pnpm records atomically.

The npm selector request budget also reserves both UTF-16 escape units for
supplementary Unicode before JSON serialization. Parser/runtime bytes and the
customer helper's absolute path remain unchanged.

Validation is in the source-parser, canonical composition and installed native
probe suites. Local deterministic checks are separate from fresh AMD64/ARM64
installed-image evidence, rich corpus agreement and whole-pipeline resource
acceptance. Production routing, Yarn and remaining ecosystems, canonical
export/matching, platform integration, licenses/maintenance and human dev
acceptance remain open. M046 S03 is incomplete.

Primary format references:

- [pnpm lockfile documents](https://pnpm.io/lockfile)
- [pnpm configuration dependencies](https://pnpm.io/config-dependencies)
- [pnpm lockfile file types](https://github.com/pnpm/pnpm/blob/main/pnpm11/lockfile/types/src/lockfileFileTypes.ts)
- [pnpm lockfile types](https://github.com/pnpm/pnpm/blob/main/pnpm11/lockfile/types/src/index.ts)

The preparation record retains the exact Git blob identities for the two type
sources; these lookups are development evidence and never per-scan API calls.
