"""Frozen64 selection corpus plus one explicit installed-ownership regression."""

from .corpus import CORPUS, case
from .oracle import inp, occ
import hashlib

PROVIDER_CORPUS = (
    *CORPUS,
    case(
        "provider-installed-python-ownership",
        "python",
        {
            "requirements.txt": "pip==99.99.99\n",
            "site-packages/pip-26.0.1.dist-info/METADATA": "Metadata-Version: 2.3\nName: pip\nVersion: 26.0.1\nRequires-Dist: packaging>=24\n\n",
            "site-packages/pip-26.0.1.dist-info/RECORD": "",
        },
        ["pypi:pip@26.0.1"],
        note="Provider retains installed metadata separately; no pip99 declaration or guessed packaging selection.",
    ),
)

# Explicit provider-only oracle, not inferred from an engine result. The root
# below is this synthetic collection, not an assertion about a project or venv.
probe = PROVIDER_CORPUS[-1]
metadata = "site-packages/pip-26.0.1.dist-info/METADATA"
record = "site-packages/pip-26.0.1.dist-info/RECORD"
inputs = [
    inp("requirements.txt", disposition="outside-provider-ownership", reason="direct-frontend-owned"),
    inp(metadata, "python-installed-metadata"),
    inp(record, "python-installed-record", disposition="supporting-metadata", reason="no-selected-identity"),
]
for source in inputs:
    source["sha256"] = hashlib.sha256(probe["files"][source["path"]].encode()).hexdigest()
probe["expected"].update(
    semantic_schema="m046-provider-probe-oracle-v1",
    oracle_scope="provider-owned metadata only; fixture collection root, not project/venv ownership",
    inputs=inputs,
    occurrences=[
        occ("pypi:pip@26.0.1", metadata, "headers:Name,Version", selection="installed-metadata", activation="unknown")
    ],
    relationships=[],
    declarations=[],
    declaration_records=[],
    references=[],
    roots=["."],
    applications=[],
    environment_records=[],
    fidelity={
        "discovery": "unassessed",
        "parsing": "unassessed",
        "enumeration": "unassessed",
        "version_selection": "unassessed",
        "graph": "unknown",
        "environment": "unknown",
    },
)
