# M050: Approval of reviewed semantic changes

[Owner scope: scanner #167](https://github.com/sourcebastion/sourcebastion-scanner/issues/167).

Outcome: a maintainer can review an intended semantic change, commit its exact
approval through the normal pull-request process and pass the existing upgrade
gate. An unapproved change still fails, with a useful summary and the entry to
paste. [Acceptance evidence](ACCEPTANCE.md).

- [S01: Exact approval and instructive failures](S01-PLAN.md).
- [S02: First transition and maintenance process](S02-PLAN.md).

The ledger, schema, matcher and first transition already shipped in #162.
M050 reuses them and improves failure messages, naming
changed dimensions/cases and finding counts, and explaining the fresh output
path required to preserve the original diff. No second approval mechanism,
service, permission or bypass flag is introduced. No source-authored oracle,
comparison rule, fingerprint format or existing approval was changed.

## Trust and authority

Approval is a reviewed repository commit. Maintainers/reviewers and the GitHub
review process are trusted; the JSON entry is an audit record, not independent
proof that GitHub approved it. The gate reads maintenance evidence and an exact
ledger, writes its diff report and exits. It does not edit an oracle, authorize
an unrelated transition, merge a PR, publish an image or deploy a service.

Malformed evidence or approvals fail. An unmatched diff remains red. New oracle
bytes or differences require fresh review; there is no automatic baseline
refresh or wildcard. Keep the original report and rerun with a fresh output
path after the reviewed commit. The ledger's existing schema and the existing
fingerprint format stay unchanged. Broader policy or authority changes remain
owner decisions.

Two bounded slices are the scope. Customer configuration, new contracts,
new infrastructure, deployment/recovery work and changing what the gate
compares are excluded. Existing native qualifications are reused; no new
scanner release is required for this repository maintenance path.
