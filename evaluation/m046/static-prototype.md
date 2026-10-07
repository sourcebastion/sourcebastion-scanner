# Static inventory frontend experiment

This is an engine-neutral static Python evaluation frontend for M046 S01.
It is not connected to the production scanner and does not select cdxgen,
SCALIBR or extended Syft. The substantive extended-Syft comparison, typed
lock/graph adapters and reviewed architecture remain required.

The registry considers recursively discovered `.in`, `.txt` and `.pip` files,
including hidden paths. Conventional requirements/constraints names, exact
local includes and explicitly mapped paths can contain bare declarations;
ambiguous bare custom files and prose remain ignored. PEP 621 `pyproject.toml`,
literal `setup.cfg` and a conservative `setup.py` AST subset have typed adapters.
Pipfile locks and standard `pylock.toml`/named variants have bounded typed lock
adapters. Other known manifests and locks are reported as unsupported, with separate inventory, export and
matching states. An explicit mapping is data, not permission to execute or
fetch anything. No repository code, package manager or metadata API is called.

The manifest adapters retain indexed field locators, runtime/build/test/optional
scopes, normalized extras, markers, root Python compatibility and explicitly
declared first-party name/version identities. Static strings, lists and literal
constants in a single unconditional standard `setup()` call are admitted without
importing or executing the module. Relative imports, callable/import rebinding,
computed values and executable statements are refused. CFG extras retain the
original key spelling, including normalized legacy dash/case option aliases;
one-line semicolons separate requirements, while dangling
multiline requirements retain marker semicolons. CFG defaults, interpolation,
`file:`/`attr:` references, dynamic inventory metadata and dependency groups are
explicitly outside this subset. Mandatory PEP621 name/version, known dynamic
fields and explicit build-system requires are checked; first-party versions use
PEP440 version parsing, rather than requirement parsing. Recognized Poetry, PDM,
uv, Setuptools, Hatch, Rye and Pixi tool sections admit only the small explicit
metadata-only key registry. Dependency/resolver controls and unknown keys in
those tools report unsupported rather than disappearing behind complete coverage.
Unrelated tool configuration (such as Black) is outside this inventory registry.
The adapter inventories declarations; it is not a full descriptive metadata
validator or an effective installation resolver. Pins
from different manifest files or runtime/build/optional scopes are never silently
combined into an asserted installation. Root activation and transitive graph
fidelity remain unknown where the source does not establish them.

Repeated declarations retain distinct locators but share context selection work,
avoiding quadratic repetition for a large same-package list. Manifest parse
admission shares the remaining 100000-record budget and source
deadline. AST token count (100000) and nesting (32) are bounded before AST
allocation. Semantic expansion shares the global dimension/work ceilings. Known
source changes during discovery or reads fail the whole inventory, discarding
previous selections rather than retaining a partial result from a changed epoch.

The grammar retains original byte hashes, logical source line locators,
PEP 508 markers, normalized extras, hashes and original version declarations.
Includes and constraints are references, not installed package edges.
Constraints preserve their role through nested includes. Exact selections
use the intersection of evidenced pins and compatible sibling declarations;
PEP 440 equivalent/local versions are compared semantically. Ranges without
an evidenced compatible pin remain unresolved. Constraint extras, unsupported
options and direct references are refused conservatively. Marker activation
and unevidenced transitive relationships remain unknown.

Marker context admission uses the pinned packaging 25.0 tree to prove flat
conjunction equivalence and narrow complementary-predicate disjointness.
Unproved overlapping contexts with differing declaration signatures are
unsupported. All declarations contribute to environment fidelity, even when
no version was selected; unsupported known formats have unknown environment.

Root ownership is retained when a parent is refused or an include traversal
budget interrupts resolution. Shared inputs have root-specific occurrences;
an include target is not promoted to an unrelated independent root. Quoted
literal filenames are unquoted once, with embedded quotes and whitespace
preserved. Refused URL references emit stable codes without their payloads.

`Source` pins a controller-supplied root, opens ancestors/files descriptor
relatively without following links and bounds discovery, byte reads and time.
It checks metadata across reads and before return, and rereads retained inputs
to compare hashes even when a same-size rewrite retains identical timestamps.
Discovered nested-directory metadata is checked around the final byte pass,
so tested insertions after discovery refuse the result too.
The final pass performs at most one extra bounded read per retained input;
the text budget counts retained source bytes, not cumulative two-pass I/O.
This detects tested source changes, but cannot establish persistent custody
or a globally atomic snapshot. The outer reviewed isolation boundary must
provide immutable source inputs. Controller root ancestors and the installed
frontend code/runtime are trusted. These helpers are not a production jail.

The lock tranche preserves exact locked occurrences with original group/field
locators, hashes, markers, extras and root/package Python compatibility. Pipfile
custom categories retain group scope; direct/transitive classification remains
unknown without a manifest relationship. Pipfile metadata hash/requires/sources
are structurally checked when supplied. Missing required metadata permits only
explicit partial fragment enumeration with unknown activation; it never proves
lock freshness or integrity. The original minimal Pipfile corpus input was
corrected to this negative contract and a complete positive was added. This is
corpus/oracle v3 (61 cases); earlier 60-case v2 evidence remains bound to its
original source and is not reassessed using the new oracle.

The pylock subset supports named locks, stable versioned wheel/sdist sources,
SHA256/SHA512 assertions and informational dependency selectors by name/version/
marker. Artifact filenames follow standard name > path > URL precedence and
must agree with the declared wheel/sdist identity. Sources are never read,
downloaded or installed. Credentials/query-bearing references and external/local
source trees are refused. Missing source entries remain labelled fragments;
multi-use environment/group selection, artifact dates and unimplemented selectors
remain explicit unsupported data. Edges are retained only when a selector
identifies one lock occurrence. Missing/ambiguous targets and overlapping variants
with unproved marker separation report partial coverage; no guessed edge or
unconditional installation claim is emitted. All scopes/edges stay source/root
aware; cross-file installation selection remains unimplemented.

Lock admission charges a shared structured-record budget before retention for
packages, dependency selectors, artifacts, hash assertions, extras and environment
records. JSON duplicate keys/nonfinite constants and TOML duplicate/malformed data
are refused. Initial standard-library JSON/TOML allocation is bounded by source
bytes and the outer resource boundary; this does not establish aggregate resource
acceptance. The lock-only edge ceiling (100000) is also proposed, not frozen.

Proposed ceilings remain **unfrozen**: 100000 traversal entries, depth 64,
2 MiB/file, 256 MiB retained text, 150-second wall deadline, 100000 parsed
records, 100000 records per semantic dimension, include depth 64 and 4096
targets/root. Internal parsing also bounds logical lines (16 KiB), marker
nesting (32), boolean terms (128) and resolution work (5000000 steps).
Numeric runs are capped at 128 digits before version-library conversion;
version-selection conversion errors become stable refusal codes.
Cross-root expansion charges the semantic dimension ceiling before append.
Global source/expansion failures discard package selections and emit failed
inventory; format/include refusals remain explicit partial coverage.

`static_cli.py` encodes an entire result before stdout emission, with a 64 MiB
limit including the trailing newline. Overflow produces a fixed-code failed
result, never a truncated success JSON. Serialization shares the source wall
deadline. It can run in Python isolated mode
from a customer-named working directory without importing source modules:

```sh
rtk proxy /trusted/python -I -B /trusted/evaluation/m046/static_cli.py \
  --root /controller/synthetic-source
```

Trusted preparation pins packaging 25.0 to the recorded wheel SHA256 in
`requirements-static.txt`; its wheel metadata lists Apache and BSD licenses.
Local prototype tests use packaging 25.0 and Python 3.13.5. That is diagnostic
development verification; it is not the required pinned native Python 3.14
offline/runtime proof. `m046-static.yml` runs native Python 3.14.8 AMD64/ARM64
jobs with hash-verified preparation, the built-in synthetic corpus and raw
traces. The runner records starting/ending frontend/shared source and corpus
hashes, interpreter/tracer/library identities, and fails unexpected process or
socket calls. The fixed scrubbed HOME points to controller scratch; the initial
local diagnostic without this value observed failed Python-startup NSS socket
attempts and is not accepted. These namespaces still expose host reads; they
are not the production boundary. Whole trace review remains an independent
gate. The 24 pip-text and four static-manifest
fixtures and six typed-lock cases match the independent rich oracle locally; other formats do not
claim supported semantic agreement. Native/process/network/write audits,
overflow/performance distributions, SBOM validation, frozen-advisory matching,
cache identity and production integration remain separate acceptance work.
