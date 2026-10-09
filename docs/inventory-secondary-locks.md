# Conservative Ruby/PHP lock enumeration

The inactive source composer now preserves the locked package/version evidence
in the original Ruby and PHP corpus fixtures. All original fixture bytes and
the historical oracle remain unchanged; source-authored full canonical
expectations record the new located occurrences and independent coverage.
No Ruby/PHP command, Gemfile evaluation, Composer plugin or installation runs.

Bundler support is deliberately narrow: one GEM remote, literal numeric
unplatformed gem versions, the ruby platform and explicit specs/dependency
sections. Registry URI identity is hashed without retaining credentials.
Multiple sources, native platform alternatives, git/path/plugin sources,
ambiguous duplicates and missing required sections refuse the input.
Dependency requirements, Ruby runtime and checksum sections retain partial
coverage; source package dependencies produce located graph losses rather than
guessed edges. No root ownership or installed activation is inferred by name.

Composer supports literal numeric locked versions (including normalized `v`
prefixes), with runtime/development package groups retained separately. Branch
and prerelease selections, local/path or virtual packages, aliases/platform
controls and malformed structural metadata remain explicit partial coverage.
Missing lock content-hash metadata does not erase independent package/version
facts. Hash syntax does not prove the lock agrees with any current manifest.
Require/provide/replace/conflict controls remain unassessed, with located graph
losses and no canonical edges. Duplicate package names refuse the whole input.

Different source files retain distinct analysis scopes and occurrence IDs even
when purls agree. These packages assert locked source evidence, not installed
state or an authenticated registry artifact. Existing manifest/provider and
legacy scanning paths remain separate; this finite subset does not establish
universal ecosystem support. The owner’s 2026-10-09 scope decision removes
legacy scanner parity as a requirement; acceptance uses the documented subsets
and explicit unsupported dispositions. Native evidence and the complete S03
acceptance review remain separate gates.

The reader boundaries follow the upstream
[Bundler lock parser](https://github.com/rubygems/rubygems/blob/master/lib/bundler/lockfile_parser.rb)
and [Composer lock schema](https://github.com/composer/composer/blob/main/res/composer-lock-schema.json).
Source bytes, deadlines, semantic checks and record quotas use the existing
shared composition pipeline, including final source validation and whole-job
refusal on exhausted budgets.

The compatibility pass also replaces nullable Pydantic field annotations in
the contract/provider with `Optional[...]`, preserving their published schema
while allowing evaluation on the package's declared Python 3.9 minimum.
`python -m scripts.verify-inventory-python-runtime` checks actual imports, four
unchanged mixed fixture package/version facts and repeatable canonical bytes.
It is a finite source-checkout compatibility probe, not installed wheel or
native release acceptance.
