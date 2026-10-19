# M052 S03: common scanner concurrency

Owner instructions on 2026-10-19: use one scanner implementation for development
and staging, enable concurrent tools on one code source, raise the supported
limit to ten for future scanners, and give the setting a descriptive name.
This is a bounded extension of the active platform M052 work, not a new budget.

Use the existing ThreadPoolExecutor and subprocess scanner wrappers. No new
scheduler, service or recovery machinery. The shared scanner defaults to ten
concurrent enabled tools; `SOURCEBASTION_MAX_CONCURRENT_SCANNERS=1..10` can lower
that bound for a deployment. Keep one migration-cycle fallback for the old name
so existing explicit serial/resource limits are not silently ignored. The new
name takes precedence. Repository-job concurrency remains a separate setting.

The scanner owns tool processes and their existing timeouts. Configured result
order and finding identities remain unchanged; failures wait for bounded
already-running tools and clean their raw output. Trust the existing worker and
runtime administrators. CPU/memory limits still bound the container; no measured
capacity or ten-fold speedup is claimed.

Acceptance: overlap ten inert components using thread barriers, enforce bounds
and failure cleanup, and reuse the existing native serial/parallel scan with the
same source and advisory snapshot on AMD64 and ARM64. Publish through the normal
reviewed version/digest release. Bind the corresponding installed platform
validator and verify the common runtime on staging; development live changes
follow its existing owner coordination. No migration, key rotation or data
rewriting is needed.

The separate checkout-Job/shared-volume replacement is awaiting the owner's
workspace-storage choice: staging currently has no StorageClass. It does not
block this concurrency change and is not claimed complete by this slice.
