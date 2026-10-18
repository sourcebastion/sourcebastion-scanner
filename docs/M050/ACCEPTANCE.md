# M050 acceptance: reviewed semantic transitions

The two slices in [owner issue #167](https://github.com/sourcebastion/sourcebastion-scanner/issues/167)
are implemented and verified. The existing reviewed-commit mechanism is reused;
there is no new approval service, permission, bypass flag or comparison change.

## Requirement evidence

| Requirement | Evidence |
| --- | --- |
| Ledger, schema and stable normalized fingerprint | `evaluation/m046/accepted-upgrades.json`, its schema, and `inventory_upgrade.transition`; introduced by #162 in 9faf1c0 and refined in ea88bbd. Existing fingerprint format is unchanged. |
| Exact match passes; changed identity or malformed entry refuses | `tests/test_inventory_upgrade_approval.py` covers each identity field, byte changes, observed/case changes, malformed/duplicate entries and oracle mismatch. All 24 focused tests pass with the improved failure guidance. |
| Failure names the difference and prints a usable entry | CLI replay reports 63 changed cases and coverage dimensions, retains the complete diff and prints its exact proposed entry. Completing the printed rationale/PR number and pasting it back changes exit1 to exit0 for the same actual proof. Output also names finding counts and explains the fresh output path. |
| Approval does not loosen the oracle/comparison or cover new findings | Candidate proof must match the current independent oracle. Original diff remains review-required inside a passing report. Tests reject unreviewed semantic/finding changes and snapshot mismatch; equal same-snapshot findings preserve a corpus approval. |
| Fix partial enumeration before the first approval | The first approval commit's parent already contains the examined-disposition/source-hash/parser guards. The 110-test approval/maintenance/input-outcome suite passes. |
| Record S05's exact transition | The existing first entry names PR162. A fresh structural comparison of immutable Git oracle bytes finds exactly 222 additions of only the three outcome fields, zero removals/value/case-set changes. |
| First transition works on real native evidence | Digest-verified AMD64 and ARM64 native artifacts from successful release39109155329 each reproduce the same approved 63-case diff over 64 cases. Empty ledger rejects; the completed printed entry and the committed default ledger each pass. |
| Process documented using normal review | The maintenance runbook's Upgrade review gives the inspection, append/review and rerun steps. The ledger records why and under which PR a transition was accepted. No oracle is generated from observations. |

## First accepted identity

| Field | Value |
| --- | --- |
| Baseline oracle SHA-256 | `3fd21f9d1e0b4f9ae128a0dceb2a94a6043d780faa8c09e0ea85a320b1bb5ab2` |
| Candidate oracle SHA-256 | `0fe1f2177e2d4743e17794befaf10099a68439924b7b9d41e3e54ce834cc601b` |
| Normalized diff fingerprint | `cb6a613f4f17191352191ae49339afad36283df9298cf46d18c5d044af4aca18` |
| Reviewed change | [PR162](https://github.com/sourcebastion/sourcebastion-scanner/pull/162) |

The immutable baseline is the oracle before af6e138; the current source-authored
oracle is still the exact candidate above. The validator fix predates approval;
M050 changed neither oracle nor the approval entry.
[Original native CI38094267046](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/38094267046)
passed before PR162 merged. Its retained audit records the same approval on both
architectures; the original 222-addition review is in
[PR162's independent review](https://github.com/sourcebastion/sourcebastion-scanner/pull/162#issuecomment-6101291979).

## Current real-evidence replay

Reused native proofs from the already successful
[v2.1.2 release run39109155329](https://github.com/sourcebastion/sourcebastion-scanner/actions/runs/39109155329):

| Architecture | Native proof artifact | Verified archive SHA-256 |
| --- | --- | --- |
| AMD64 | inventory-source-expectations-amd64, ID12130081824 | `f4f0aa5c5b65a82de2f9d6efd97fb15df6bd6e1cb7bc867040162d5744e4dd4a` |
| ARM64 | inventory-source-expectations-arm64, ID12129758964 | `80c4ff75737834356005351ff5d2247d30f109d386594f96e7a6bbdc51965394` |

The downloaded ZIP bytes matched GitHub's artifact digests before reading the
actual native proof. On each architecture, the unchanged base/current oracle
pair produces 64 compared cases and 63 changed cases. An empty temporary ledger
exits1 with the pasteable proposal. Completing that printed entry with the
already-reviewed PR162 rationale gives the exact committed entry and exits0.
The default committed ledger also exits0. The original full diff is retained.
No proof was fabricated from the oracle, no source oracle was edited, and no
fresh image build/publication was needed for this replay.

Maintainers and GitHub review are trusted: an entry is an auditable reviewed
commit, not a cryptographic assertion that a human review occurred. M050 adds
only failure guidance to the existing gate and records the formal process.
Scanner behavior, schemas/fingerprint versions, approvals, permissions, hosts
and release identities remain unchanged.
