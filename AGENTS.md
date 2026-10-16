# Guidance for AI agents

Read this before planning, designing, reviewing or changing anything in this
repository. It applies to every agent (Codex, Claude and others).

## Direction: autonomous, bounded subsystems

SourceBastion is moving toward systematic agency. Design each subsystem
(deployment barrier, monitoring and alerting, scanning, provider ingestion,
backup and recovery, and so on) to run itself, within hard limits.

1. **Owns its own processes.** A subsystem starts, checks, restarts, retries,
   scales and recovers its own components without a human for routine faults.
2. **Authority stops at its boundary.** It has its own identity, credentials,
   data and directories, and cannot modify another subsystem's state,
   configuration, credentials or processes. Monitoring may restart its own
   exporters, never the application. The deployment barrier owns deployments,
   and no service account can alter its inputs. Scanners run foreign code with
   no writer credentials.
3. **Crosses boundaries only through explicit contracts.** Effects on another
   subsystem go through a versioned interface that the receiving side
   validates. Never borrow, share or copy another subsystem's credentials.
4. **Resilient and fail-closed.** It survives its own faults. When it cannot
   proceed safely, it stops and reports rather than widening its own authority.
5. **Observable and transparent: observe broadly, act narrowly.** Information
   is not hidden. Every subsystem publishes its state, decisions, failures and
   needs in a form humans and other subsystems can read without reaching
   inside it, and a subsystem gets read access to the data it needs to do its
   job well. Authority to *change* things stays bounded (rule 2); visibility
   does not. The exceptions are secrets (credentials and keys are never
   exposed, only their identities and health) and customers' private data
   (source code, findings and personal data are visible only to the
   subsystems that serve that customer).
6. **Humans keep the system in balance.** People resolve conflicts between
   subsystems, set priorities and budgets, approve new contracts and
   cross-boundary authority, and decide what the milestones don't record.

When proposing or reviewing a design, answer: what does this subsystem own,
what can it affect outside itself, how does it recover on its own, and what
escalates to a human? What does it publish, and what data does it need to
see? Flag any design where one subsystem needs authority over another, or where
useful information is hidden without a secrecy or privacy reason. Prefer a contract or an escalation to a shared credential.

## Working rules

- **Milestone → slice → task.** Plan and track work as `Mxxx/Sxx/Txx` in
  `docs/Mxxx/` (README, `Sxx-PLAN.md`, `ACCEPTANCE.md`). PRs start with
  `Task: Mxxx/Sxx/Txx`.
- **Gaps are owner decisions.** If a needed choice (provider, scope, default) is
  not recorded in the milestone docs, present options and a recommendation;
  never fill it in as if decided.
- **Purposeful runtime names.** Installed paths, accounts, units and roles are
  named by purpose (for example `/opt/sourcebastion/deployments`), never by
  milestone ID.
- **Few integrations.** Prefer existing providers over adding new ones, and
  show the integration count and cost when proposing options.
- **Least privilege by default,** with privileged operations confined to
  purposeful, root-owned locations.
- **Minimize the time a PR stays open (cross-review).** The author never
  merges their own PR. Claude reviews and merges Codex's PRs; Codex reviews
  and merges Claude's. Reviewing the other agent's PRs **takes priority over
  your own work**: check for them before starting or resuming a task, because
  an open PR blocks more than new work advances. Merge as soon as CI is green and
  the review is clean. A flaky check gets one rerun, then a fix. Docs-only PRs
  may be reviewed and merged by whichever agent or owner is available first.
  Keep PRs small and rebased. Escalate to the owner only for decisions,
  disagreements between agents, or actions the permissions reserve for them.
- **Live actions** follow the standing authorization in the active milestone's
  README (for M044: staging allowed, development read-only/disposable,
  production none).
