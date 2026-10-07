# Local CycloneDX experiment

Draft engine-neutral S04 preparation; no selected engine or production wiring.
The existing canonical static Python inventory is authoritative. Exporting it
does not improve unsupported Node/Go/Rust parsing or make its graph resolved.

The serializer emits CycloneDX JSON1.6 using unmodified schemas from specification
commit55343ba19dee1785acf1ce9191540d5fd7b590db (Apache2 license included).
Schema bytes are hash-pinned in code. All external schema references resolve to
the vendored SPDX/JSF schemas; remote retrieval refuses. Schema validation also
checks the admitted flat export profile, BOM references and dependency endpoints.
This validator is not a general imported-SBOM parser.
The schema's quadratic dictionary uniqueness fallback is replaced by exact
canonical-value uniqueness after admitting only bounded JSON without floats.
Boolean/integer distinctions and object/array semantics are independently
compared with the pinned standard validator; no schema constraints are removed.

Each selected exact occurrence becomes a library component with a canonical
PyPI purl, occurrence identity, standard source evidence and namespaced typed
properties. Pins describe declared/locked selections, not installed packages.
Hashes remain evidence properties: lock artifact hashes do not establish the
hash of an installed library. Range-only declarations and constraints remain
in authoritative metadata and do not become versioned matching components.
Root/application/input dispositions, conditional environment information and
relationships remain explicit. Analysis roots are not invented applications.
Properties require a SourceBastion-aware reader; generic consumers do not gain
these semantics by accepting a schema-valid BOM.
Occurrence IDs use the previously reviewed Go adapter namespace/JSON encoding,
including non-ASCII and HTML/JavaScript separator vectors. IDs remain stable
across the two export formats when their canonical occurrence facts are equal.

Standard dependency edges are a conservative subset. Locator-disambiguated
endpoints must be unique; conditional/unknown activation and unsupported edge
semantics remain properties with explicit projection losses. Missing adjacency
never becomes an empty dependency list. Composition/graph policy reports unknown
completeness; no transitive graph is inferred from flat requirements.

Inventory, export and matching statuses remain separate. Source inventory is
unchanged on export failure. Serialization is fully buffered under64MiB; deadline,
tree depth/node/text and occurrence/edge bounds refuse rather than truncate.
Schema evaluation needs an outer CPU/AS/wall process boundary; cooperative
checks alone are not a production isolation boundary. Native test jobs use
1GiBAS/120CPU/150wall/64MiBfile limits. Large-corpus validation, actual production
image packaging of the schema tools and shared global scan deadline remain open.

Compatibility identity includes exporter/spec/schema hashes, inventory contract,
selected input evidence and explicit producer/code/registry/config/environment
policy. This is not a whole-repository commit identity or the final M036 cache
key. Real matching adds separately verified consumer/config/advisory identities;
changing one must invalidate incompatible results. Imported build SBOM admission
and platform persistence remain separate work.
The API receives producer digests as caller assertions, not authenticated
provenance. Diagnostic controllers must bind actual code/input/config bytes
before and after execution; publisher verification is a separate check.

Local consumer diagnostics use the publisher-verified Grype0.119.0 binary and
the frozen October6 advisory snapshot, with updates/external sources disabled
inside a read-only-source network namespace. Initial custom/hidden inputs each
produce the four retained pip26.0.1 advisories, and two roots produce eight
occurrence-bound matches. Grype preserves BOM references but emits null source
locations for the standard evidence. A trusted ID-bound occurrence recovery
layer joins only exact IDs and validates the source hash, root, standard evidence
and selected version. It preserves the original Grype finding/locations fields
and adds explicit recovered context, including unknown activation. Finite CVSS/
EPSS decimals survive; nonfinite values refuse. Each recovered record is charged
against aggregate serialized-byte/node budgets before copying its context;
purl-only joining cannot choose a root. Final-source diagnostics,
native consumer/resource tests, historical/adversarial matching and S04 acceptance
remain pending. Trace uncertainty never changes raw matching facts into an
all-attempts isolation claim. The parent trace gate remains open.

Refs scanner#88/#92; the platform SBOM browser remains M047.
