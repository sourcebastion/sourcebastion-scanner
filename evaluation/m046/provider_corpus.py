"""Frozen64 selection corpus plus one explicit installed-ownership regression."""

from .corpus import CORPUS, case

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
