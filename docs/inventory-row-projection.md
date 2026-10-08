# Inactive inventory row projection

`sourcebastion.inventory.row_projection.project_rows` materializes one exact typed
canonical Inventory into immutable records for a future findings-store read
projection. It has no runtime caller, SQL metadata, migration, upload, matching
authority or storage-readiness receipt. The returned dataclasses are forgeable;
a server must independently validate canonical and accepted-run association and
recompute its expected rows. This helper is not that server validator.

The existing canonical serializer and contract validation establish one detached
snapshot before hashing or deriving rows. Every canonical collection is preserved
as a context, occurrence, relationship or evidence record. Global coverage and
other top-level evidence remain snapshot detail; inputs and context associations
have separate rows. Input ordinals refer to canonical order. Unknown context stays
unknown; no ecosystem or root completeness is inferred. Matching is separate and
is not manufactured by an inventory projection.

Occurrence list columns are scalar. Scope/group/extra membership facets are
distinct; original arrays remain exact in occurrence detail. Name/version ordering
is recorded lexical order with NULL versions last and canonical ID as tiebreaker,
never semantic version inference. Persisted integer ranks avoid a combined
long-Unicode-name/version index. Additional UI sort/normalization policies and
physical index choices remain separate work.

Rows sort by (table,key). Their projection digest uses the version domain followed
by an eight-byte big-endian length-framed canonical JSON header and, for each row,
framed table/key/scalar-columns JSON and framed detail JSON. Encoding is UTF8,
sorted keys, compact separators, ensure_ascii=True and allow_nan=False. The header
binds projection version, exact canonical artifact SHA and source SHA. This digest
is distinct from the canonical artifact digest and conveys no account/run identity.

The caller must supply positive exact integer max_rows and max_bytes with no
default. Exact expanded row count is checked before JSON-mode model copying and
rank sorting; input/context and distinct facet expansion are included. The full
framed projection size is logical accounting, including repeated
scalar/evidence bytes; it does not measure SQL rows/indexes/TOAST/WAL/bloat or set a
production quota. Header and every generated row count toward these ceilings;
refusal returns no truncated projection. Row JSON is encoded incrementally, with
byte admission before each encoded chunk is appended; individual encoder string
chunks remain bounded by canonical scalar limits. Sorting scratch is bounded by
the admitted row count and canonical collection limits, and is not charged as SQL
storage. Peak process resource confinement must
also bound canonical serialization/validation, model copying, Python sorts and
per-record JSON construction between shared allowance callbacks. This module does
not reset or widen scanner canonical limits.

Batch manifests, quota reservations, publication CAS, closure hooks, retention and
reuse, authenticated matching, granular producer coverage, server distribution,
database proofs and M047's first-page performance gate remain unimplemented here.
