# M046 S03 Python declaration and marker helpers

`sourcebastion.inventory.python_manifests` ports the reviewed S01 static grammar
into the production namespace. It accepts exact source bytes for the maintained
S02 format IDs `python-pyproject`, `python-setup-cfg` and `python-setup-static`.
Typed declarations retain source hashes, semantic locators, original locator
case, canonical dependency names, ranges/pins, markers/extras and runtime,
build/test/optional scope. Application metadata and Python compatibility stay
separate from dependency declarations. This grammar does not infer installation,
project ownership, lock selection, graph edges or group activation.

Only a conservative literal setup.py AST subset is admitted: known setuptools
setup aliases, literal constants/containers and one static setup call. Imports
are interpreted as syntax; source modules, factories, setup hooks and package
managers are never invoked. Rebinding, computed/conditional metadata and unknown
setup fields remain unsupported. setup.cfg interpolation, file directives,
inherited defaults, option collisions, unimplemented legacy metadata dependency
fields and unknown dependency controls remain visible refusals. Recognized tool
dependency controls beside PEP621 cannot silently disappear. Unknown project or
build metadata fields refuse rather than produce a complete empty declaration
set. All failures discard the document's partial declarations.

The parser enforces existing input/line/record/nesting/token/deadline ceilings.
Production Python 3.14 supplies tomllib. On a general package installation with
Python 3.9/3.10, missing tomllib produces `unsupported-toml-runtime` for TOML
without preventing static setup.cfg/setup.py parsing. This is an explicit
capability limit, not a declaration that older-runtime TOML is supported.

`sourcebastion.inventory.markers` uses pinned packaging 26.3's bounded parsed
tree and narrow internal evaluator. Its public `Marker.evaluate` fills host
defaults, so this helper does not call it. Every expression variable must have
an explicitly recorded environment value before active/inactive is returned.
Missing variables, extra/group selection and unsupported comparisons remain
unknown. Both-variable comparisons refuse because the upstream evaluator would
otherwise interpret one variable name as a literal. No target is inferred from
the worker. A marker result does not activate an optional group on its own.

Flat conjunction ordering and exact complementary predicates support narrow
equivalence/disjointness proofs. Other expressions remain opaque. Callers must
provide the shared pipeline accounting/epoch check callback; these helpers do
not create a new pipeline allowance. Pinned private API behavior requires
regression review on packaging upgrades.

The native image workflow adds a finite installed-wheel foundation probe: strict
module-path/version/hash checks; explicit/missing marker decisions; canonical
contract roundtrip and refusals; repeated grammar parsing of the five relevant
inputs in the frozen 64-case corpus. Both inventory probe scripts explicitly
refuse optimized Python before assertions can be removed. Artifacts report exact
loaded inventory module hashes, Python/packaging/Pydantic versions and result
digests. Container restrictions are workflow requests: these artifacts provide
no kernel/cgroup/network-attempt proof or whole-pipeline resource qualification.

These modules are not yet wired into S02 discovery or the scanner result route.
S02 continues to label these format adapters unsupported. Source-aware canonical
composition, selection provenance, full Python lock adapters, non-Python support
matrix, export/matching and S03–S07 acceptance remain required. The finite native
probe is not a claim that the full rich corpus or dependency pipeline passes.
