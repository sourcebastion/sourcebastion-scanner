# Source-aware npm inventory foundation

`compose_source` now adds static `package.json` and registry npm lock v2/v3
(`package-lock.json`, `npm-shrinkwrap.json`, or explicitly mapped files) to the
existing single discovery/Source epoch/semantic ledger. This foundation is not
wired to the production scan route. pnpm, Yarn, npm lock v1, workspaces, linked
packages, alias protocols and peer endpoint resolution remain separate work.
They cannot be reported as fully covered by these adapters.

## Source authority

Manifest dependency tables retain runtime, development, optional and peer
scopes. npm's optional-over-runtime override is respected; optional peers keep
both conditions. Scripts and project modules are data only. An exact literal
SemVer can evidence a declared source pin; ranges, tags, aliases and URLs do not
become selected versions through a resolver or a sibling lock. Inventory never
claims these declarations are installed.

Lock `packages` entries retain exact nested `node_modules` source paths, separate
occurrence IDs, versions, integrity digests and hashed resolved URI assertions.
Raw URLs and credentials do not enter the inventory. Unsupported declaration/edge
expressions retain their source locator and source SHA256 with a null canonical
range and fixed unresolved diagnostic, including when no endpoint exists. A source URI hash does not
authenticate an artifact or registry. A supplied `name` differing from its
module-path name is currently an unsupported alias, not an identity match.
Missing artifacts or checksums never imply an installed package.

Endpoint selection searches explicit ancestor `node_modules` entries, then
checks the selected version against the declaration using the pinned npm
parser. It does not select among equal names or purls. A nearer refused entry
blocks fallback to an ancestor. Absent, incompatible, protocol-specific and
peer selectors stay typed unresolved, with no fabricated edge. Optional edges
retain conditional scope and unknown activation; no host target is inferred.
Lock source graph fidelity remains partial, independently of enumeration and
version fidelity. Reachable source direct/transitive roles do not prove
installation or production reachability.

Named application metadata establishes an explicit source root, including a
nullable application version. Manifest and lock roots share identity only when
same-directory explicit application name/version and every dependency-table
name/range/scope/optional condition agree, with exactly one candidate. Folder
proximity alone never assigns ownership. Unreachable lock entries retain null
root ownership; lock scope remains available.

Unsupported workspace/overrides/resolutions/bundling/OS/CPU/libc/engine controls,
nested pnpm controls, dependency/install metadata and acceptDependencies
retain partial coverage rather than disappearing. Peer-only and extraneous lock
flags preserve peer/unknown scope and partial context rather than asserting runtime. A malformed input does not
invalidate independently proved inputs. A shared budget or final source-epoch
failure clears all consumable inventory, including Python evidence. JSON depth
is checked before decoding; duplicate keys, nonfinite/oversized numbers,
malformed types and control-bearing dependency strings are refused. Traversal,
source bytes, occurrence/edge/structure limits and final source revalidation
remain the enclosing composer's existing limits.

## Maintained npm grammar and custody

`npm_selectors.py` sends bounded version/range strings to the installed trusted
`node_selectors.cjs`, which imports only the vendored npm `semver` **7.8.5**
parser. It uses strict versions and npm's default prerelease policy, without
coercion, project loaders, install scripts, network enrichment or a resolver.
The parser has no runtime npm dependencies. Its ISC license and all 53
published files are included unchanged. Primary sources:
[npm semver](https://github.com/npm/node-semver/tree/6e05b7637396ac66522cff8731f07cfe0ef49a29),
[npm lock specification](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/).

Trusted preparation verified package archive SHA256
`d85045d4300d7d57c891336b95df532e73f34c22ffcd222452b6d08b9d127d5d`,
registry SHA512 integrity and registry ECDSA metadata signature. Every packaged
file matched immutable upstream commit
`6e05b7637396ac66522cff8731f07cfe0ef49a29`. The installed vendor manifest pins
all file hashes and records those primary identities; the wrapper verifies it
before a range batch. Registry signature verification is not Sigstore
attestation verification or native-runtime acceptance.

The helper inherits the remaining outer deadline and semantic ledger. Its
minimal environment excludes `NODE_OPTIONS`, `NODE_PATH` and project hooks;
its working directory is the installed trusted module, not customer source.
V8 string code generation is disabled. Query counts, strings, terms, digit
length, request/response bytes and process timeout are bounded. Runtime errors
publish fixed codes without copying raw dependency diagnostics. The enclosing
controller still owns cgroup/process-tree cancellation, immutable installed
code and resource isolation. The existing image's Node release/closure and
whole-pipeline performance/license qualification remain S06 work; this helper
is not an independently enforced sandbox.

Upgrades require replacing exact primary bytes, retaining license/source and
signature/integrity evidence, regenerating the hash manifest and literal pin,
and rerunning adversarial selector/source composition plus installed native
image proofs. Never fetch npm packages or consult a forge API per customer scan.

## Validation scope

Tests and native probes exercise nested versions, path-shadowing refusal,
range/prerelease mismatch, scoped names/build metadata, source URI privacy,
optional/peer/dev conditions, explicit application pairing, malformed JSON,
shared budgets and final source mutation. Native diagnostics retain actual
installed module, helper and 53-file vendor identities plus actual Node version.
The repeated 64 corpus digests remain repeatability records, not full rich
oracle agreement. These finite proofs do not close S03, qualify resources,
prove network syscall absence, wire matching, or authorize a deployment.

The native provider artifact upload also retains partial trusted-preparation
logs when preparation was attempted and failed. Failure evidence does not
qualify a provider binary, manifest or native protocol as successful.
