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

The proof reuses hosted smoke's source-free advisory generation. Before fixture
admission it binds the installed inventory source, reviewed native binary hashes,
explicit private config/environment, actual database status and every bounded
advisory file. Binary hashes derive from the official release archives already
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
