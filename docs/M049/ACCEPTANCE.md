# M049 acceptance

Status: **open; no full milestone acceptance**. Owner budget: one engineering
day including prior work, reviews and verification; stop at half the total
budget without an accepted shipped outcome. Splits do not restart it.

| Outcome | Current evidence | Remaining acceptance |
| --- | --- | --- |
| Notices and source directions beside all bundled objects | #203 retains 30 original license/author files across 15 component/version groups; notices bind all 19 library files per architecture | Independent review; real available source reference; both released image architectures checked |
| Source available from scanner GHCR repository | #204 pins five source archives and four build-recipe archives; deterministic tar and OCI manifest prepared | Correspondence review; main-only publication; anonymous immutable-digest retrieval |
| Native drift visible before release | #202 approved and merged; synthetic additions refuse; both architectures' current wheel identities recorded | #205 candidate report/draft PR exercise and independent review; installed-image closure |

The source tar SHA256 is
`47c099826215dc33520595a9a51d47df05a633078d28adb9cc8ce9680d896d63`.
The prepared OCI manifest SHA256 is
`88740e3f4ef899fc63aad828497bf0f1cf535fb1878098c66a4ca3a768a2dbf2`.
Neither digest by itself proves publication or qualifies an image.

Release uses the existing reviewed release PR and protected release environment.
No release tag is moved and no environment approval is bypassed. The release
identity, published image index and native manifest digests, mirror retrieval
result and independent acceptance must be recorded here before #164 closes.
Historical M046 wheel/image observations remain historical.
