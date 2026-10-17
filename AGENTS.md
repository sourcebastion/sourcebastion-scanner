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

## Guardrails: standard practice, budgets, shipped outcomes

These come first. They exist because M044 spent 17 days and about 110k lines
rebuilding what Kubernetes, PostgreSQL and GitHub already do, and shipped
nothing. Each new proof obligation became another implementation task, and
merged components were treated as progress.

1. **Standard practice first.** Before designing or building, name the
   standard tool for the concern (Kubernetes, PostgreSQL, GitHub, the existing
   providers) and use it. A custom component needs a short written reason and
   owner approval *before* work starts. If a task asks you to build something
   a standard tool already does, stop and propose the standard tool instead,
   even if the milestone says otherwise.
2. **One outcome, explicit exclusions, and a trust statement.** A milestone
   states one user-visible outcome ("staging serves the new build and passes
   smoke") and lists what it excludes. It names trusted administrators,
   supported faults, data-loss limits and manual recovery. It never states a
   proof of absence ("no path can bypass"). A standard tool doesn't satisfy a
   stronger requirement automatically, so say which requirement it meets.
3. **Budgets cover everything, with a stop rule.** The budget includes design,
   tests, evidence, reviews, splits and diagnostics. If there's no live
   accepted result at half the budget, stop and return a specific owner
   decision. Renaming or re-scoping a milestone doesn't reset the clock. A new
   unresolved prerequisite stops that branch and goes to the owner. It doesn't
   automatically become another slice.
4. **Evidence must close a decision.** Evidence is worth producing when it
   closes a named release or risk decision: restore verification, migration
   timing, an incident's original logs. Reuse unchanged qualifications. Don't
   add bespoke receipt layers, proof-package-only PRs or PRs that only
   re-split earlier PRs.
5. **Small vertical slices, few open at once.** The roughly 800-line PR guide
   applies to a bounded behaviour change. A large design split into many green
   PRs is still a large unvalidated design. Keep at most one unfinished
   component stack per milestone. Check the live result before adding
   siblings.
6. **Review for necessity as well as correctness.** Reviewers ask "is this
   needed, and is there a standard way?" before "is this correct?"
7. **Daily owner checkpoint.** Long-running goals report daily:
   - shipped behaviour (what works now that didn't);
   - the current critical blocker;
   - time and token spend;
   - the next demo.

   Accepted outcomes count as progress; code completion and issue counts
   don't. Infra milestones get a human design review before implementation.

The subsystem direction above is built from standard tools. Bounded authority
means RBAC, database roles and scoped credentials, not custom controllers.

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
  an open PR blocks more than new work advances.
  Work the queue **oldest first: any PR open for more than a day goes to the
  front**. A stale draft gets finished, split or closed by its author, not
  left open. Merge as soon as CI is green and
  the review is clean. A flaky check gets one rerun, then a fix. Docs-only PRs
  may be reviewed and merged by whichever agent or owner is available first.
  Keep PRs small and rebased: **aim for under about 800 changed lines of
  code per PR** (generated evidence, fixtures and lockfiles excluded), each one
  mergeable on its own. Split larger work into a stack of reviewable units —
  for example contract and validation first, then the component, then
  integration — rather than one PR of thousands of lines. Escalate to the owner only for decisions,
  disagreements between agents, or actions the permissions reserve for them.
- **Live actions** follow the standing authorization in the active milestone's
  README. For M051: staging allowed; development read-only and disposable
  fixtures only, with every live change owner-run; production none.
  Deleting retained data or keys, credential rotation, provider dashboards,
  anything with cost, new contract or protocol versions, and unrecorded
  decisions are always owner-only.
