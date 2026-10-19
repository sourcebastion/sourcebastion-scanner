# M052 scanner work

The platform owns the [M052 customer journey](https://github.com/sourcebastion/sourcebastion-platform/tree/main/docs/M052).
The owner requested one scanner implementation across development/staging and
enabled concurrency of up to ten scanner tools per source tree on 2026-10-19.
Use the existing thread pool, subprocess wrappers and reviewed image release.

- [S03: common concurrency plan](S03-PLAN.md)
- [Acceptance status](ACCEPTANCE.md)

Shared checkout/scan Pods need a workspace-storage decision and remain outside
this code change. No new scheduler, service, provider, database or migration.
