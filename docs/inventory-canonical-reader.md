# Inactive canonical artifact reader

`read_canonical` accepts exact builtin bytes plus the caller's lowercase SHA256
claim, shared allowance callback and optionally tighter structural limits. It
returns the existing typed Inventory only after digest agreement, bounded
structural admission, strict syntax/duplicate/nonfinite checks, the existing
canonical schema validator, and exact equality with its canonical export.
Whitespace, reordered keys and omitted default fields are not the exact export.
The canonical contract is imported, not copied into another schema.

The frozen ceilings are64MiB,2million value/container nodes, depth32 and2MiB
decoded strings. The initial lexical pass excludes object keys from node count
and bounds raw string spans conservatively by six times the decoded byte ceiling;
the existing structural walker enforces exact decoded limits before models.
JSON numeric parsing also bounds number-token length before integer conversion
or rejects nonfinite floats. Every canonical numeric export fits these token
bounds. The exact bytes are immutable across the duplicate check and subsequent
strict JSON-mode model parse. These two parses are deliberate: Python strict
models do not admit JSON arrays as tuples. The first tree is discarded before
building the typed model.

Callbacks occur during hashing, lexical traversal, decoded numeric/object hooks,
and around decoder/shape/model/canonical serialization. They cannot interrupt
the standard decoder's large arrays, model validation, structural walker or
serializer. A separately reviewed parent process supervisor with kernel resource
isolation must bound peak memory/CPU and terminate on the existing shared
deadline. This module provides no such supervisor, HTTP stream limits or reset
credit and makes no maximum-shape resource/performance acceptance claim.

Digest agreement authenticates no assertion. Caller authorization, accepted-run
association, source and controller custody, uploaded artifact availability,
matching evidence, validator distribution and key/revocation checks remain
independent prerequisites. There is no route, uploader, SQL writer, matching
invocation or runtime caller of this reader. Generated local typed artifact
tests are decoder proofs, never evidence of an admitted upload or scan.
