# Scanner artifact verification

The release workflow verifies the reviewed `.github/semgrep-artifacts.json`
before preparing a release. All four Linux wheels (glibc/musl, amd64/arm64)
must match their SHA-256 pins and pass `pypi-attestations==0.0.30` verification.
The accepted publishing identity is the upstream
`semgrep/semgrep-proprietary` repository's `pro-release.yml` workflow. The
verifier binds that identity to the signing certificate and checks signatures
and transparency-log evidence. Changing this allowlist requires code review.

Docker builds install the exact wheel from this lock after independently
checking its hash. They do not select the newest version at build time. This
lock covers Semgrep itself, **not its transitive Python dependencies** or all
other software in the image. It is publishing provenance, not proof of a
reproducible build or that the source has no vulnerabilities.

`Propose verified scanner artifacts` runs Mondays at 06:37 UTC on main. It
discovers a stable PyPI version, rejects yanked/missing platforms, verifies all
wheels without installing or executing them, then proposes only the Semgrep
lock/version changes in a PR. It never approves, merges, or releases changes.
No pin files change if verification fails. A candidate artifact is retained
for review/recovery if GitHub cannot open the PR.

The weekly job uses the existing `sourcebastion-bot` GitHub App, not
`GITHUB_TOKEN`, to push the candidate and open its PR. The organization and
repository restrictions on Actions-created/approved PRs stay unchanged.
App-created PRs trigger normal `pull_request` checks; no manual CI dispatch
or Actions write permission is needed. Wait for those checks before merging.

Provision the existing App's ID and private key as environment secrets
`SOURCEBASTION_BOT_APP_ID` and `SOURCEBASTION_BOT_PRIVATE_KEY` in the repository's
`scanner-maintenance` environment, with deployment branches restricted to
`main` only (no tags). Do not create another App. The App installation must
include this repository and grant Contents and Pull requests write access.
The workflow mints a short-lived installation token only after verification
finds a change, scopes it to this repository and those two permissions, and
checks the App slug before writing. The pinned token action revokes it at job
completion. `GITHUB_TOKEN` remains read-only and checkout persists no token.
Missing credentials or insufficient App permissions fail the job; there is
no fallback to a personal token or relaxed organization policy.
Weekly scheduling begins only after this workflow reaches main.

The integrity workflow also runs on PRs targeting main or
`bot/scanner-refresh-20260928`, and on pushes to that latter branch. This
exercises the integrated result after the stacked PR merges into #46 without
publishing anything. Once #46 merges, the temporary branch triggers can be
removed.

Network reads retry at most three times (5/15-second delays) for connection
errors, HTTP 429, and selected 5xx responses. Missing attestations, unexpected
publishers, signature errors and hash mismatches fail closed. Verification
unavailability blocks release; it never falls back to unchecked installation.

KICS remains at its reviewed digest. Neither the candidate job nor this
Semgrep verifier updates or claims to authenticate KICS publisher provenance.
Establishing that provenance is a separate prerequisite for automatic KICS
updates.

Manual read-only verification:

```sh
python -m pip install pypi-attestations==0.0.30
python scripts/scanner_artifacts.py verify
```

Prepare a candidate in a clean review branch (writes the two pin files only
after successful verification):

```sh
python scripts/scanner_artifacts.py candidate --version 1.178.0
```
