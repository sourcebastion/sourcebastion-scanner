# M046 source inventory support and remaining release gates

This describes the internal canonical source composition API and its reviewed
fixtures. The released customer dependency scan still uses the legacy path.
An adapter, a passing fixture or a provider observation does not enable the new
route or establish whole-repository completeness. Native proof and release
acceptance must identify the exact code, registry, configuration and helpers.

| Input | Package enumeration | Version certainty | Dependency edges |
| --- | --- | --- | --- |
| Requirements `.txt`, `.in`, `.pip`, custom hashed locks and explicit mappings | Content-validated declarations; includes and constraints retain source context | Exact declarations or compatible constraint selection; unpinned/conflicting versions remain unresolved | Flat files provide no package edges; includes and selection declarations remain separate |
| PEP 621, optional dependency groups, `setup.cfg`, static `setup.py` | Supported static declarations in separately located analysis scopes | Exact static versions only; ranges and dynamic metadata stay unresolved | No resolved package edges are inferred from declarations |
| Recognized `.dist-info/METADATA` | Own observed installed package identity; `Requires-Dist` remains declarations | Version asserted by that metadata only; no borrowed project root or resolved child version | No child endpoint or installed reachability inferred; egg-info remains unsupported |
| Pipfile specification 6 | Supported registry lock entries; missing structural metadata or artifact assertions leave partial coverage | Retained exact lock versions, independently of enumeration completeness | No edges invented from a flat package table |
| Poetry 2.0/2.1, uv 1 revision 3, PDM 4.5.0 | Supported conservative lock subsets; unknown source/resolver controls remain explicit omissions | Retained exact lock versions; groups, markers, optionality and Python compatibility do not prove installed activation | Source selectors bind uniquely evidenced endpoints; ambiguity stays unresolved; PDM extras and group variants remain distinct |
| pylock 1.0 and filename variants | Supported conservative registry artifact subset; missing artifact sources leave partial coverage | Exact lock versions; explicit selector versions remain exact | Evidenced source endpoints only; no installed reachability claim |
| npm manifests and package-lock | Static declarations and supported lock entries; unsupported source controls remain partial | Manifest ranges are unresolved; supported lock entries retain exact versions | Source-bound lock selectors; no installed/workspace ownership inferred |
| pnpm and Yarn classic/modern locks | Supported conservative registry subsets; incomplete package resolution and unsupported protocols remain partial | Exact versions when evidenced by admitted entries | Literal source selectors and maintained range grammar; peers and unresolved alternatives do not acquire endpoints |
| Go module metadata | Maintained `x/mod/modfile` source parsing requires the separately prepared trusted helper | `require` versions are minimum-version declarations, not selected versions; `go.sum` is checksum history | Module selection and package edges remain unresolved; no project commands or registry resolution |
| Cargo manifests and registry locks | Static declarations and admitted registry/sparse lock entries retain distinct contexts | Manifest ranges remain unresolved; supported lock entries retain exact versions | Source package-ID selectors only; local/git/workspace ambiguity does not become a registry edge |
| Modern Gradle dependency locks | Supported conservative coordinate/configuration entries | Exact asserted lock versions | Flat lock entries do not establish package edges or project ownership |
| NuGet `packages.lock.json` v1/v2 | Conservative package entries remain distinct per framework/RID table; project references and v3 aliases remain unsupported | Explicit locked versions and independently validated SHA512 hashes; missing hashes retain partial coverage | Same-table named endpoints with reviewed numeric release ranges; floating/prerelease ranges and RID fallback remain unresolved |
| Bundler GEM locks | Single registry/ruby-platform numeric package subset; multiple sources and native platforms remain unsupported | Explicit unplatformed locked versions; runtime/requirement/checksum controls remain unassessed | Located graph losses; no endpoints inferred from gem names |
| Composer locks | Conservative numeric package subset; runtime/development groups remain distinct | Explicit locked release versions; branch/prerelease/local/virtual variants remain unassessed | Require/provide/replace/conflict controls produce located losses; no guessed edges |
| Maven POM, `packages.config`, Ruby/PHP executable manifests | Recognized inputs; canonical source adapters are currently unsupported | No selected canonical package records are admitted | No canonical edges admitted |

`coverage.discovery`, `enumeration`, `version_resolution`, `graph` and
`environment` are independent. Complete selected-version coverage over zero
retained occurrences does not prove any package was examined. Fragment locks
can retain exact versions while discovery/enumeration remain partial. An
inventory stage marked complete still does not imply complete graph or target
environment coverage. Canonical project roots and installed environments remain
nullable unless their own source evidence establishes them.

The bounded restricted provider can retain observations for additional formats,
including Java, .NET, Ruby and PHP. Those observations are separate evidence;
they are not silently promoted to canonical packages, ownership or graph
semantics. The original .NET fixture now retains its explicit locked package,
with partial coverage for the invalid fixture hash. Original Ruby/PHP fixtures
now retain their explicit locked packages, with partial Composer metadata
coverage where appropriate. The historical oracle and all original source
bytes remain unchanged. That characterizes the current
boundary; it does not establish preservation of the legacy matcher’s packages
or findings for a future replacement route.

The original 64 fixtures have full source-authored record, reference, coverage
and stage expectations. Native AMD64 and ARM64 run 37895511556 passed all 64
cases with identical canonical inventory digests and exact installed/check-out
module hashes. Final integration checks and the S03 acceptance decision are
recorded on scanner issue 91. This finite corpus does not establish arbitrary
format coverage, numeric host/kernel budgets, production compatibility or
whole-milestone acceptance.

Scope decision (2026-10-09): the owner confirmed that the scanner has no users
and legacy package/finding parity is not an acceptance requirement. S03 uses
the documented supported subsets and explicit unsupported dispositions.
Additional Ruby/PHP source, platform and version forms are future coverage
work; they do not block acceptance of the current subsets. This decision does
not permit guessed versions, invented edges or complete coverage claims for
unsupported inputs. Production routing, matching admission, platform
ingestion/artifact access, release performance and human development
acceptance remain separate open work.
