# Native canonical SBOM and Grype proof

The native AMD64 and ARM64 hosted smoke jobs now run one independently authored
fixture through the installed canonical inventory, CycloneDX exporter, actual
Grype binary and occurrence recovery. The released directory-scanning route is
unchanged. Synthetic recovery guards remain separate.

Two source-located `requests==2.19.1` observations have equal package identity and
distinct occurrence IDs. One marker stays unknown without a target environment.
A version range remains unselected and is excluded from the export. Both selected
IDs must receive the known advisory through an exact reviewed ID and namespace:
[GHSA-x84v-xcm2-53pg / CVE-2018-18074](https://github.com/advisories/GHSA-x84v-xcm2-53pg).
Additional advisories are permitted and retained. Recovery uses exact artifact
IDs, preserves complete original report bytes and compares semantic finding
objects and canonical contexts. It never joins by package name or purl.

The v3 fixture also retains `pip==26.0.1` from `scripts/python-build.in` and
`.github/python-locks/build.txt`. The latter contains an asserted hash from the
reviewed synthetic source fixture; no package download or artifact verification
is implied. Each distinct pip occurrence must independently receive all four
original regression advisories, accepting only the corresponding exact
ID/namespace aliases:

- [GHSA-wf93-45jw-7689 / CVE-2026-8643](https://github.com/advisories/GHSA-wf93-45jw-7689)
- [GHSA-qwm4-qh6w-59xr / CVE-2026-13346](https://github.com/advisories/GHSA-qwm4-qh6w-59xr)
- [GHSA-jp4c-xjxw-mgf9 / CVE-2026-6357](https://github.com/advisories/GHSA-jp4c-xjxw-mgf9)
- [GHSA-58qw-9mgm-455v / CVE-2026-3219](https://github.com/advisories/GHSA-58qw-9mgm-455v)

Four source-located selected occurrences become four components. A versionless
range remains excluded. Additional findings remain untouched; this is a minimum
known-advisory gate, not a hard-coded total finding count. Receipts retain the
exact occurrence IDs and original match ordinals satisfying each alias group.
The historical v2 fixture remains unchanged. Current database identities are
recorded separately from the original investigation snapshot; no historical
equal-snapshot or complete product-route acceptance is claimed.

The proof reuses hosted smoke's source-free advisory generation. Before fixture
admission it binds the installed inventory source, reviewed native binary hashes,
explicit private config/environment, actual database status and every bounded
advisory file, with at most 32 files, 32 directories, depth 8 and 4 GiB of
aggregate advisory bytes. This file bound is separate from the 2 GiB container
memory limit; files are hashed in 1 MiB chunks. Binary hashes derive from the official release archives already
pinned by the image build. Admission has a separate 330-second limit. Composition,
export, real consumer, recovery and final identity checks share one 150-second
source deadline. Stdout is capped at 2 MiB and stderr at 256 KiB per child; failure
kills/reaps its process group and retains available partial evidence.

The outer container uses a nonzero caller UID, no network, read-only source,
advisories and root filesystem, no capabilities, no new privileges, two CPUs,
2 GiB RAM without additional swap, 256 PIDs and a 16 MiB temporary filesystem.
CI uploads canonical JSON, CycloneDX, original Grype output, admission records,
diagnostics and a separate receipt, including available artifacts on failure.
Canonical hashes and stage states stay unchanged after export and matching.

This finite integration proof does not establish whole S04 acceptance, production
controller custody, same-UID administrator fencing, complete kernel traces,
aggregate CPU-time enforcement, database publisher signatures or release and
deployment readiness. Different native jobs may prepare different advisory
snapshots; compare findings across architectures only under equal snapshot
identity. The historical 64-case corpus and its expectations remain unchanged.
