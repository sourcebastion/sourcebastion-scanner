# M046 S02 local discovery foundation

The maintained registry and bounded source reader live in `sourcebastion.inventory`.
They implement S02 discovery and pip input/include/constraint provenance. The
existing production scanner route is not changed by this slice. S03 supplies
canonical graph and ownership semantics; S04 supplies real matching before the
new route can be integrated. No per-scan forge API or source build is used.

A trusted controller opens `Source(root, limits)` and calls
`discover(source, config=DiscoveryConfig(...))` while retaining that source for
later adapters. The root must be an immutable controller-admitted checkout;
parent ancestry and host isolation remain the controller's responsibility.
The reader uses descriptor-relative no-follow/nonblocking I/O, regular-file and
same-device checks, metadata/byte revalidation and bounded traversal. Symlinks,
foreign devices and special files yield visible unsupported records; they are
never followed. Ordinary subdirectory depth omissions retain safe siblings.
A source epoch change invalidates documents; a missed final deadline also
refuses consumption. This is detection within one operation, not persistent
custody or a universal filesystem isolation guarantee.

The default maxima are the accepted S01 ceilings: 100,000 traversal entries,
64 directory levels, 2 MiB/file, 256 MiB retained parsed text, 150 seconds
(clamped to the outer deadline by the controller), 64 include levels,
4,096 targets/origin and 5,000,000 reference checks. Limits may only decrease.
Logical pip lines have an additional conservative 16 KiB cap. The pip record
allowance is shared across input documents rather than restarted per file.
S06 must enforce shared cgroup CPU/memory/wall/PID and complete-pipeline limits.

Registry `sourcebastion.inventory-registry/1` records exact conventional names
for Python, npm/pnpm/yarn, Go, Rust, Java, .NET, Ruby and PHP. Known formats
without implemented adapters are located and hashed with `unsupported` status;
filename recognition alone never claims parsing. Requirements candidates include
all `.in`, `.txt` and `.pip` files, including hidden paths. Content validation
accepts syntactic dependency evidence; ambiguous bare names in arbitrary text
are ignored unless explicitly mapped or included. Malformed mixed prose does
not leak a partial set of accepted requirements. Standard requirements filenames
and explicit mappings may contain bare declarations. Direct URLs, index/options,
interpolation and unsupported syntax retain stable reasons; URLs/credentials
are not copied into diagnostics.

`DiscoveryConfig` accepts immutable tuples of `(root-relative-path, format)`
mappings and ignored root-relative paths. It accepts only maintained format IDs,
no imports, commands, downloads, globs or outside-root authority. An ignored path
covers its subtree and stays visible as an intentional omission. `.git`, `.hg`
and `.svn` metadata are ignored at any level; there is no blanket hidden-file
exclusion and `.github/python-locks` remains discoverable. Includes cannot
bypass ignores or a conflicting explicit format mapping. Missing mapped files
remain failed records. Config and registry identities are independently hashed.

Pip `-r`/`-c` references preserve source path, physical line, literal target,
origin and requirement/constraint context. Duplicate documents are read once;
separate references and contexts are retained deterministically. Cycles and
limit refusals are located. A constraint's context stays `constraint` through
nested includes. No constraint becomes an installed dependency and no include
becomes a package-to-package edge. These are source observations, not canonical
project-root IDs. S03 will decide canonical ownership and selected versions.

The returned `Discovery.status` describes this discovery operation only. It is
not inventory completeness, export success, matching success or absence of
vulnerabilities. Empty/unrecognized repositories do not establish an empty
complete inventory. `parsed_input_digest` covers read input hashes only, not
the complete checkout. Per-input statuses are `parsed`, `ignored`, `unsupported`,
`failed` or `bounded-omission`; source/global refusals remain separate. Raw
source content stays in the controller-held reader and is never diagnostic text.

The pip syntax adapter uses the existing reviewed Semgrep closure's pure-Python
`packaging==26.3` artifact, declared explicitly in runtime inputs and all four
runtime locks without re-resolving unrelated dependencies. S01 experiments used
packaging25.0; this production slice reruns the descriptor/grammar/discovery and
frozen corpus input regressions against 26.3. S03 must compare full canonical
semantics, and S06 must qualify the complete final release/native closure.

Tests include real symlink/FIFO/parent-swap/replacement/deadline boundaries,
custom hashed and hidden paths, include/constraint/cycle/ignore provenance,
ceiling reductions/refusals, deterministic repeats, all 64 source-bound S01
fixture inputs and the project's actual `scripts/python-build.in` and hidden
hash locks. The frozen fixture JSON is copied from reviewed evaluation head
`d98fbd0fb9c5563999a5c061a12fb68191fddd86`; its expectations are original S01
semantics, not new assertions of S02 package/edge accuracy.
