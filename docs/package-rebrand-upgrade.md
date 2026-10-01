# Scanner package rebrand upgrade

This is a breaking package/configuration change. Existing digest-pinned images
are unchanged; do not advance downstream scanner pins until their consumers
have migrated and been tested together.

- Install the `sourcebastion-scanner` distribution and import `sourcebastion`.
- Invoke `sourcebastion`; the former console-script alias is removed.
- Rename repository configuration to `.sourcebastion.yaml`, or explicitly pass
  the existing file with `--config` during a controlled migration.
- Rename deployment environment variables and Actions secrets/variables from
  `EZ_APPSEC_*` to `SOURCEBASTION_*`. This code does not rename stored secrets.
- Update adapter file paths to `sourcebastion/cedar_adapter.py` and direct Git
  dependency distribution names before changing the pinned scanner revision.
- Regenerate dashboard configuration with `sourcebastion_version` and update
  Prometheus queries to `sourcebastion_findings_total`.

Real repository names, registry paths, historical release links, and immutable
artifact digests are resource identities, not display names. Do not replace
them mechanically. The dashboard aggregation job mints its write token for the
repository it actually checks out; customer dashboard destinations remain
separately configured.

Release validation must include installed-wheel CLI/version tests, hosted scan
contract tests, and downstream platform adapter conformance. Merging this PR
does not update the dev or staging scanner image pin.
