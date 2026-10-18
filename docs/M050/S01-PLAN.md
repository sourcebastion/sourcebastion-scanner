# M050 S01: Exact reviewed approvals and useful failures

## Tasks

- [x] **T01: Retain the exact transition ledger and schema.**
  `evaluation/m046/accepted-upgrades.json` and its schema already landed in
  #162. Entries require immutable baseline-oracle bytes, candidate-oracle
  bytes, the complete normalized diff fingerprint, rationale and PR number.
  Malformed or duplicate entries reject; no wildcard or bypass flag exists.
- [x] **T02: Match only the reviewed transition.** The native candidate must
  match the source-authored oracle and its digest before approval is considered.
  Changed baseline, candidate or fingerprint reject; approvals self-expire when
  either oracle or the observed diff changes. Architecture/report metadata
  does not create a semantic difference. Original raw hashes and diffs remain.
- [x] **T03: Make an unapproved change actionable.** The failure names changed
  dimensions/cases, missing/added cases and finding counts where applicable,
  identifies the retained full diff, and prints the exact JSON entry. It tells
  the reader to fill rationale/PR number, use a reviewed commit and rerun with
  a fresh output path while retaining the original report.
- [x] **T04: Verify the approval boundary.** Exact/pasted approvals pass;
  changed baseline/candidate/fingerprint, malformed approvals, invalid oracle
  identity, unreviewed differences and changed advisory snapshots reject.
  The actual AMD64/ARM64 proof replay also demonstrates rejection, printed-entry
  acceptance and committed-ledger acceptance. [Details](ACCEPTANCE.md).
