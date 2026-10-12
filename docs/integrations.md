# Integrations

## Jira

ez-appsec can automatically create and manage Jira issues for critical and high severity findings. When a finding is resolved (no longer detected), the corresponding Jira ticket is closed automatically.

### Setup

Set the following environment variables:

| Variable | Required | Description |
|---|---|---|
| `SOURCEBASTION_JIRA_URL` | Yes | Jira instance URL (e.g. `https://myteam.atlassian.net`) |
| `SOURCEBASTION_JIRA_EMAIL` | Yes | Email address of the Jira API user |
| `SOURCEBASTION_JIRA_TOKEN` | Yes | Jira API token ([create one here](https://id.atlassian.com/manage-profile/security/api-tokens)) |
| `SOURCEBASTION_JIRA_PROJECT` | Yes | Jira project key (e.g. `SEC`) |
| `SOURCEBASTION_JIRA_ISSUE_TYPE` | No | Issue type name (default: `Bug`) |

Or pass them as CLI flags:

```bash
ez-appsec scan . \
  --jira-url https://myteam.atlassian.net \
  --jira-email bot@example.com \
  --jira-token ATATT3... \
  --jira-project SEC
```

### Behavior

- **Creates issues** for new critical and high findings. Medium and low findings are skipped.
- **Deduplicates** using a fingerprint (rule ID + file path). A fingerprint map is stored at `data/projects/<project>/jira_map.json`.
- **Closes issues** when a finding is no longer detected in the latest scan. A comment is added before transitioning the issue to "Done".
- **Priority mapping**: critical → Highest, high → High.
- **Labels**: Issues are tagged with `security` and `ez-appsec` by default.

### Issue content

Each Jira issue includes:

- Severity and scanner name
- Rule ID and file location
- Finding description
- Remediation guidance (when available)
- Link to the dashboard (when `--dashboard-url` or `SOURCEBASTION_DASHBOARD_URL` is set)

### CI/CD example (GitHub Actions)

```yaml
- name: Scan and sync to Jira
  env:
    SOURCEBASTION_JIRA_URL: ${{ secrets.JIRA_URL }}
    SOURCEBASTION_JIRA_EMAIL: ${{ secrets.JIRA_EMAIL }}
    SOURCEBASTION_JIRA_TOKEN: ${{ secrets.JIRA_TOKEN }}
    SOURCEBASTION_JIRA_PROJECT: SEC
    SOURCEBASTION_DASHBOARD_URL: https://security.example.com
  run: ez-appsec scan .
```

## Slack / Teams Notifications

See the `--slack-webhook` and `--teams-webhook` options on the `scan` command. Set `SOURCEBASTION_SLACK_WEBHOOK` or `SOURCEBASTION_TEAMS_WEBHOOK` environment variables for CI/CD use.

## License Compliance

sourcebastion can check dependency licenses against allowed and denied lists. Licenses come from the dependency files the scanner already reads: the license each package states in `package-lock.json`, `composer.lock` and installed Python `METADATA`. Nothing is looked up online or guessed from a package name, and no extra tool is needed. The details are in [M048 S03](M048-license-evidence.md).

### Setup

Add a `license_policy` section to your `.sourcebastion.yaml`:

```yaml
license_policy:
  allowed_licenses:
    - MIT
    - Apache-2.0
    - BSD-2-Clause
    - BSD-3-Clause
    - ISC
  denied_licenses:
    - GPL-*
    - AGPL-*
    - SSPL-*
  undetermined_severity: medium   # or low
```

### How it works

Each package gets one result: **permitted**, **denied** or **undetermined**.

- **Expressions are parsed.** `MIT OR GPL-3.0-only` is a choice, so it's permitted when either branch is. `MIT AND GPL-3.0-only` requires both, so it's denied when either term is.
- **Denied** (high severity): a term matches the denied list. Denied wins over allowed.
- **Undetermined** (medium, or low if configured):
  - no license is stated
  - the stated value isn't an SPDX expression
  - a `LicenseRef-*` isn't named in the policy
  - with an allowed list, a license isn't on it

  Undetermined is never treated as permitted.
- **Entries are licenses, not expressions.** Wildcards match one identifier: `GPL-*` matches `GPL-3.0-only`, not `LGPL-2.1-only`. `X WITH E` entries must be exact. Allowing `X` allows it with any exception, but an exception never lifts a denial of `X` unless that exact pair is allowed.
- **Conflicting claims:** when a package states more than one license, the strictest result applies.
- **Vocabulary:** the SPDX license list pinned with the scanner (3.27.0).

### Running a license check

```bash
sourcebastion scan . --license-check
```

License results appear as `category: license_compliance` findings. Each finding names the package, the file the license came from (`file`, `license_locator`) and its result (`license_result`).

| Finding | `rule_id` |
|---|---|
| Denied | `license-denied-<canonical expression>` |
| Not on the allowed list | `license-undetermined-<canonical expression>` |
| Not an SPDX expression | `license-undetermined-unparsed` |
| No license stated | `license-undetermined-unstated` |

Suppress one with an ignore rule on its `rule_id`.

### Scan output

| Field | Description |
|---|---|
| `license_summary.total` | Resolved packages evaluated (locked, installed or imported) |
| `license_summary.declarations_not_assessed` | Declared dependencies with no resolved package to read a license from (commit a lockfile to check them) |
| `license_summary.permitted` / `denied` / `undetermined` | Packages per result |
| `license_summary.coverage` | `complete` or `partial`. When partial, some dependency files weren't read and packages may be missing. |
| `license_summary.unassessed_inputs` | Dependency files that weren't assessed |
| `license_summary.license_list_version` | SPDX license list used |
| `license_packages` | Every package with its stated licenses and result |

### Migrating from the syft-based check

- **Rule IDs changed.** `license-unknown-<value>` is now `license-undetermined-<canonical expression>`, `license-undetermined-unparsed` or `license-undetermined-unstated`. `license-denied-<value>` now uses the canonical expression, for example `license-denied-GPL-3.0-only` rather than the raw `gpl-3.0-only`. Old ignore rules don't match the new IDs; rewrite them.
- **Wildcards match identifiers, not strings.** `GPL*` still matches `GPL-3.0-only` but no longer matches a whole expression string. Entries containing `AND`, `OR` or parentheses are refused when the config loads.
- **Deny-only policies report undetermined packages.** A package that states no license, or `NOASSERTION`, is now reported instead of passing.
- **Results are per package.** The summary counts packages, not licenses.
- **syft is no longer used.**

### CI/CD example

```yaml
- name: Scan with license compliance
  run: sourcebastion scan . --license-check --output results.json
```
