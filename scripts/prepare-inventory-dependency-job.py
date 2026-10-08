"""CI-only source-free expected advisory facts; never a customer job allowance."""

import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import sys
import time

if len(sys.argv) != 3:
    raise SystemExit("usage: prepare-inventory-dependency-job.py ADVISORIES OUTPUT")
advisories, output = map(Path, sys.argv[1:])
os.umask(0o077)
info = output.lstat()
if (
    not stat.S_ISDIR(info.st_mode)
    or info.st_uid != os.geteuid()
    or stat.S_IMODE(info.st_mode) != 0o700
    or any(output.iterdir())
):
    raise ValueError("private-empty-preparation-output-required")
helper = Path(__file__).with_name("verify-inventory-real-grype.py")
functions = runpy.run_path(str(helper), run_name="source_free_advisory_binding")
deadline = time.monotonic() + 330
binding = functions["advisory_binding"](advisories, deadline)
for row in binding["files"].values():
    if row["metadata"][2] & 0o022 or row["metadata"][3] != os.geteuid():
        raise ValueError("unsafe-prepared-advisory-permissions")
snapshot = advisories / "snapshot.json"
if binding["files"]["snapshot.json"]["bytes"] > 2 * 1024**2:
    raise ValueError("prepared-snapshot-byte-budget-exceeded")
raw = snapshot.read_bytes()
if hashlib.sha256(raw).hexdigest() != binding["files"]["snapshot.json"]["sha256"]:
    raise ValueError("changed-prepared-advisory-snapshot")
status = json.loads(raw)["database"]
if status["valid"] is not True:
    raise ValueError("invalid-prepared-advisory-status")
value = {
    "schema_version": "sourcebastion.native-dependency-preparation/1",
    "binding": binding,
    "status": status,
    "helper_source_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
    "scope": "CI-only source-free maintained-generation preparation. Its330s helper deadline is outside the separate actual controller job and grants no production admission credit. The job must hash all admitted content again within its one150wallledger. Parent kernel/custody/release admission remains separate.",
}
encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
if len(encoded) > 65536:
    raise ValueError("prepared-manifest-byte-budget-exceeded")
with (output / "advisory.json").open("xb") as handle:
    handle.write(encoded)
