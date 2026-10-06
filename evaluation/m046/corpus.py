"""Handwritten S01 inputs and expectations; never derived from engine output.

This is a review candidate, not an independently approved oracle. Exact packages
and evidenced package-to-package edges are scored separately from declarations.
Ranges, conditional activation and malformed/unsafe files remain coverage work.
"""

import json


def case(name, ecosystem, files, packages=(), *, edges=(), declarations=(), disposition="parsed", note="", links=None):
    return {
        "id": name,
        "ecosystem": ecosystem,
        "files": files,
        "symlinks": links or {},
        "expected": {
            "packages": list(packages),
            "edges": list(edges),
            "declarations": list(declarations),
            "disposition": disposition,
            "note": note,
        },
    }


def jslock(packages):
    return json.dumps({"name": "fixture", "lockfileVersion": 3, "packages": packages})


CORPUS = [
    case("python-requirements", "python", {"requirements.txt": "requests==2.32.3\n"}, ["pypi:requests@2.32.3"]),
    case("python-input", "python", {"requirements.in": "requests==2.32.3\n"}, ["pypi:requests@2.32.3"]),
    case("python-custom-input", "python", {"deploy.in": "flask==3.0.3\n"}, ["pypi:flask@3.0.3"]),
    case(
        "python-custom-hashed-lock",
        "python",
        {
            "dependencies-prod.txt": "requests==2.32.3 " + chr(92) + chr(10) + "    --hash=sha256:" + "a" * 64 + "\n",
        },
        ["pypi:requests@2.32.3"],
        note="Synthetic hash exercises syntax, not download integrity.",
    ),
    case("python-hidden", "python", {".deps/requirements.txt": "urllib3==2.2.2\n"}, ["pypi:urllib3@2.2.2"]),
    case(
        "python-include",
        "python",
        {"requirements.txt": "-r locks/base.txt\n", "locks/base.txt": "requests==2.32.3\n"},
        ["pypi:requests@2.32.3"],
        note="Include is provenance, not a package dependency edge.",
    ),
    case(
        "python-constraint-only",
        "python",
        {"requirements.txt": "-c constraints.txt\n", "constraints.txt": "urllib3==2.2.2\n"},
        disposition="declaration-only",
        note="A constraint does not install a dependency.",
    ),
    case(
        "python-constraint-resolves",
        "python",
        {"requirements.txt": "requests\n-c constraints.txt\n", "constraints.txt": "requests==2.32.3\n"},
        ["pypi:requests@2.32.3"],
        note="Exact constraint intersects the required package; activation remains declared.",
    ),
    case(
        "python-marker",
        "python",
        {"requirements.txt": 'requests==2.32.3; python_version < "3.12"\n'},
        ["pypi:requests@2.32.3"],
        note="Inventory includes conditional declaration, not a claim it is installed.",
    ),
    case(
        "python-extras",
        "python",
        {"requirements.txt": "requests[socks]==2.32.3\n"},
        ["pypi:requests@2.32.3"],
        note="No guessed PySocks edge: extras require further metadata.",
    ),
    case(
        "python-range",
        "python",
        {"requirements.txt": "requests>=2.31,<3\n"},
        declarations=["pypi:requests:>=2.31,<3"],
        disposition="declaration-only",
        note="Do not match a range as an installed version.",
    ),
    case(
        "python-normalization",
        "python",
        {"requirements.txt": "Typing_Extensions==4.12.2\n"},
        ["pypi:typing-extensions@4.12.2"],
    ),
    case(
        "python-conflicting-roots",
        "python",
        {"a/requirements.txt": "requests==2.31.0\n", "b/requirements.txt": "requests==2.32.3\n"},
        ["pypi:requests@2.31.0", "pypi:requests@2.32.3"],
        note="Keep distinct roots and versions.",
    ),
    case(
        "python-pyproject",
        "python",
        {"pyproject.toml": '[project]\nname="fixture"\nversion="1.0.0"\ndependencies=["requests==2.32.3"]\n'},
        ["pypi:requests@2.32.3"],
    ),
    case(
        "python-pyproject-optional",
        "python",
        {
            "pyproject.toml": '[project]\nname="fixture"\nversion="1.0.0"\n[project.optional-dependencies]\ntest=["pytest==8.3.3"]\n'
        },
        ["pypi:pytest@8.3.3"],
        note="Optional scope must survive inventory.",
    ),
    case(
        "python-setup-cfg",
        "python",
        {"setup.cfg": "[metadata]\nname=fixture\n[options]\ninstall_requires=\n    requests==2.32.3\n"},
        ["pypi:requests@2.32.3"],
    ),
    case(
        "python-static-setup",
        "python",
        {"setup.py": 'from setuptools import setup\nsetup(name="fixture", install_requires=["requests==2.32.3"])\n'},
        ["pypi:requests@2.32.3"],
        note="Static AST only; execution is forbidden.",
    ),
    case(
        "python-dynamic-setup",
        "python",
        {
            "setup.py": 'from pathlib import Path\nPath("EXECUTED").write_text("unsafe")\nfrom setuptools import setup\nsetup(name="fixture", install_requires=compute_dependencies())\n'
        },
        disposition="unsupported",
        note="Must report dynamic metadata without executing it.",
    ),
    case(
        "python-pipfile",
        "python",
        {
            "Pipfile.lock": json.dumps(
                {
                    "_meta": {"pipfile-spec": 6},
                    "default": {"requests": {"version": "==2.32.3"}},
                    "develop": {"pytest": {"version": "==8.3.3"}},
                }
            )
        },
        ["pypi:requests@2.32.3", "pypi:pytest@8.3.3"],
    ),
    case(
        "python-poetry",
        "python",
        {
            "poetry.lock": '[[package]]\nname="requests"\nversion="2.32.3"\ndescription=""\noptional=false\npython-versions=">=3.8"\nfiles=[]\n[metadata]\nlock-version="2.0"\npython-versions=">=3.8"\ncontent-hash="fixture"\n'
        },
        ["pypi:requests@2.32.3"],
    ),
    case(
        "python-uv",
        "python",
        {
            "uv.lock": 'version=1\nrevision=3\nrequires-python=">=3.12"\n[[package]]\nname="requests"\nversion="2.32.3"\nsource={registry="https://pypi.org/simple"}\n'
        },
        ["pypi:requests@2.32.3"],
    ),
    case(
        "python-pdm",
        "python",
        {
            "pdm.lock": '[metadata]\nlock_version="4.5.0"\ngroups=["default"]\nstrategy=["inherit_metadata"]\n[[package]]\nname="requests"\nversion="2.32.3"\nrequires_python=">=3.8"\ngroups=["default"]\nfiles=[]\n'
        },
        ["pypi:requests@2.32.3"],
    ),
    case(
        "python-pylock",
        "python",
        {"pylock.toml": 'lock-version="1.0"\ncreated-by="fixture"\n[[packages]]\nname="requests"\nversion="2.32.3"\n'},
        ["pypi:requests@2.32.3"],
    ),
    case(
        "python-pylock-variant",
        "python",
        {"pylock.dev.toml": 'lock-version="1.0"\ncreated-by="fixture"\n[[packages]]\nname="pytest"\nversion="8.3.3"\n'},
        ["pypi:pytest@8.3.3"],
    ),
    case(
        "python-include-cycle",
        "python",
        {"requirements.txt": "-r other.txt\n", "other.txt": "-r requirements.txt\n"},
        disposition="malformed",
        note="Cycle must be bounded and reported.",
    ),
    case(
        "python-include-escape",
        "python",
        {"requirements.txt": "-r ../outside.txt\n"},
        disposition="unsafe",
        note="Synthetic outside.txt must not be inventoried.",
    ),
    case(
        "python-malformed",
        "python",
        {"requirements.txt": "requests===\nnot valid @@@ dependency\n"},
        disposition="malformed",
    ),
    case(
        "python-false-positive",
        "python",
        {"meeting-notes.txt": "Please discuss requests==2.32.3 next week.\n"},
        disposition="ignored",
    ),
    case(
        "node-npm-v3",
        "node",
        {"package-lock.json": jslock({"node_modules/lodash": {"version": "4.17.21"}})},
        ["npm:lodash@4.17.21"],
    ),
    case(
        "node-npm-edges",
        "node",
        {
            "package-lock.json": jslock(
                {
                    "node_modules/debug": {"version": "4.3.7", "dependencies": {"ms": "^2.1.3"}},
                    "node_modules/ms": {"version": "2.1.3"},
                }
            )
        },
        ["npm:debug@4.3.7", "npm:ms@2.1.3"],
        edges=[["npm:debug@4.3.7", "npm:ms@2.1.3"]],
    ),
    case(
        "node-npm-dev",
        "node",
        {"package-lock.json": jslock({"node_modules/mocha": {"version": "10.7.3", "dev": True}})},
        ["npm:mocha@10.7.3"],
    ),
    case(
        "node-npm-nested",
        "node",
        {
            "package-lock.json": jslock(
                {"node_modules/ms": {"version": "2.1.3"}, "node_modules/debug/node_modules/ms": {"version": "2.0.0"}}
            )
        },
        ["npm:ms@2.1.3", "npm:ms@2.0.0"],
    ),
    case(
        "node-yarn",
        "node",
        {
            "yarn.lock": '# yarn lockfile v1\n\nlodash@^4.17.21:\n  version "4.17.21"\n  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"\n'
        },
        ["npm:lodash@4.17.21"],
    ),
    case(
        "node-pnpm",
        "node",
        {
            "pnpm-lock.yaml": "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.21\n        version: 4.17.21\npackages:\n  lodash@4.17.21: {}\nsnapshots:\n  lodash@4.17.21: {}\n"
        },
        ["npm:lodash@4.17.21"],
    ),
    case(
        "node-manifest-range",
        "node",
        {"package.json": '{"name":"fixture","dependencies":{"lodash":"^4.17.21"}}'},
        declarations=["npm:lodash:^4.17.21"],
        disposition="declaration-only",
    ),
    case("node-malformed", "node", {"package-lock.json": '{"packages":'}, disposition="malformed"),
    case(
        "go-module",
        "go",
        {"go.mod": "module example.test/fixture\n\ngo 1.22\n\nrequire golang.org/x/text v0.18.0\n"},
        ["golang:golang.org/x/text@v0.18.0"],
    ),
    case(
        "go-indirect",
        "go",
        {"go.mod": "module example.test/fixture\n\ngo 1.22\n\nrequire golang.org/x/text v0.18.0 // indirect\n"},
        ["golang:golang.org/x/text@v0.18.0"],
        note="No inferred module dependency edges.",
    ),
    case(
        "go-sums-only",
        "go",
        {"go.sum": "golang.org/x/text v0.18.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"},
        disposition="declaration-only",
        note="Historical checksum entries are not selected requirements.",
    ),
    case(
        "go-local-replacement",
        "go",
        {
            "go.mod": "module example.test/fixture\n\ngo 1.22\nrequire example.test/dependency v1.0.0\nreplace example.test/dependency => ../dependency\n"
        },
        disposition="unsafe",
        note="Local replacement is unresolved; do not invent selected upstream version.",
    ),
    case(
        "rust-lock",
        "rust",
        {
            "Cargo.lock": 'version=3\n[[package]]\nname="itoa"\nversion="1.0.11"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n'
        },
        ["cargo:itoa@1.0.11"],
    ),
    case(
        "rust-edges",
        "rust",
        {
            "Cargo.lock": 'version=3\n[[package]]\nname="serde_json"\nversion="1.0.128"\nsource="registry+https://github.com/rust-lang/crates.io-index"\ndependencies=["itoa"]\n[[package]]\nname="itoa"\nversion="1.0.11"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n'
        },
        ["cargo:serde_json@1.0.128", "cargo:itoa@1.0.11"],
        edges=[["cargo:serde_json@1.0.128", "cargo:itoa@1.0.11"]],
    ),
    case(
        "rust-conflicting-roots",
        "rust",
        {
            "a/Cargo.lock": 'version=3\n[[package]]\nname="itoa"\nversion="1.0.11"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n',
            "b/Cargo.lock": 'version=3\n[[package]]\nname="itoa"\nversion="1.0.10"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n',
        },
        ["cargo:itoa@1.0.11", "cargo:itoa@1.0.10"],
    ),
    case(
        "rust-manifest-range",
        "rust",
        {"Cargo.toml": '[package]\nname="fixture"\nversion="0.1.0"\n[dependencies]\nitoa="1"\n'},
        declarations=["cargo:itoa:1"],
        disposition="declaration-only",
    ),
    case(
        "java-gradle-lock",
        "java",
        {"gradle.lockfile": "# Gradle lock\norg.apache.commons:commons-lang3:3.14.0=compileClasspath\nempty=\n"},
        ["maven:org.apache.commons/commons-lang3@3.14.0"],
    ),
    case(
        "dotnet-lock",
        "dotnet",
        {
            "packages.lock.json": json.dumps(
                {
                    "version": 1,
                    "dependencies": {
                        "net8.0": {
                            "Newtonsoft.Json": {
                                "type": "Direct",
                                "requested": "[13.0.3, )",
                                "resolved": "13.0.3",
                                "contentHash": "fixture",
                            }
                        }
                    },
                }
            )
        },
        ["nuget:Newtonsoft.Json@13.0.3"],
    ),
    case(
        "ruby-lock",
        "ruby",
        {
            "Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.1.7)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack\n\nBUNDLED WITH\n   2.5.19\n"
        },
        ["gem:rack@3.1.7"],
    ),
    case(
        "php-lock",
        "php",
        {
            "composer.lock": json.dumps(
                {"packages": [{"name": "psr/log", "version": "3.0.2", "type": "library"}], "packages-dev": []}
            )
        },
        ["composer:psr/log@3.0.2"],
    ),
    case(
        "symlink-escape",
        "python",
        {},
        links={"requirements.txt": "../outside.txt"},
        disposition="unsafe",
        note="Outside sentinel is a synthetic dependency; never follow escape.",
    ),
    case(
        "symlink-cycle",
        "python",
        {},
        links={"a": "b", "b": "a"},
        disposition="unsafe",
        note="Traversal must terminate.",
    ),
]

for fixture in CORPUS:
    if fixture["id"] in {"python-pylock", "python-pylock-variant"}:
        fixture["expected"]["disposition"] = "unsupported"
        fixture["expected"]["note"] = "Enumeration fragment: missing source records; not a complete reproducible lock."
    elif fixture["id"].startswith("node-npm-"):
        fixture["expected"]["note"] = "Enumeration fragment without paired manifest/root metadata."
    elif fixture["id"] in {"go-module", "go-indirect"}:
        fixture["expected"]["packages"] = []
        fixture["expected"]["disposition"] = "declaration-only"
        fixture["expected"]["declarations"] = ["golang:golang.org/x/text:>=v0.18.0"]
        fixture["expected"]["note"] = "go.mod require records a minimum; the transitive MVS graph is unavailable."


CORPUS += [
    case("python-product-build-input", "python", {"scripts/python-build.in": "pip==26.0.1\n"}, ["pypi:pip@26.0.1"]),
    case(
        "python-product-hidden-lock",
        "python",
        {".github/python-locks/build.txt": "pip==26.0.1 --hash=sha256:" + "b" * 64 + "\n"},
        ["pypi:pip@26.0.1"],
        note="Product filename/version regression; synthetic integrity hash.",
    ),
    case("python-pip-extension", "python", {"dependencies.pip": "flask==3.0.3\n"}, ["pypi:flask@3.0.3"]),
    case(
        "python-long-options",
        "python",
        {
            "requirements.txt": "--requirement=locks/base.pip\n--constraint constraints.txt\n",
            "locks/base.pip": "requests>=2.31,<3\n",
            "constraints.txt": "requests==2.32.3\n",
        },
        ["pypi:requests@2.32.3"],
        note="Constraint refines declaration; does not independently install packages.",
    ),
    case(
        "python-conflicting-constraint",
        "python",
        {"requirements.txt": "requests==2.32.3\n--constraint=constraints.txt\n", "constraints.txt": "requests<2.32\n"},
        disposition="malformed",
        note="Contradictory declaration/constraint cannot be matched as a selected package.",
    ),
    case(
        "python-marker-alternatives",
        "python",
        {"requirements.txt": 'requests==2.31.0; python_version < "3.12"\nrequests==2.32.3; python_version >= "3.12"\n'},
        ["pypi:requests@2.31.0", "pypi:requests@2.32.3"],
        note="No target environment supplied; retain both mutually exclusive occurrences with unknown activation.",
    ),
    case(
        "python-identical-multiple-roots",
        "python",
        {"a/requirements.txt": "requests==2.32.3\n", "b/requirements.txt": "requests==2.32.3\n"},
        ["pypi:requests@2.32.3"],
        note="One identity, two independently evidenced root occurrences.",
    ),
    case(
        "python-pylock-complete",
        "python",
        {
            "pylock.toml": 'lock-version="1.0"\ncreated-by="fixture"\n[[packages]]\nname="requests"\nversion="2.32.3"\n'
            'dependencies=[{name="urllib3",version="2.2.2"}]\n'
            'wheels=[{name="requests-2.32.3-py3-none-any.whl",url="https://packages.invalid/requests.whl",hashes={sha256="'
            + "a" * 64
            + '"}}]\n'
            '[[packages]]\nname="urllib3"\nversion="2.2.2"\n'
            'wheels=[{name="urllib3-2.2.2-py3-none-any.whl",url="https://packages.invalid/urllib3.whl",hashes={sha256="'
            + "b" * 64
            + '"}}]\n'
        },
        ["pypi:requests@2.32.3", "pypi:urllib3@2.2.2"],
        edges=[["pypi:requests@2.32.3", "pypi:urllib3@2.2.2"]],
        note="Complete structural sources/hashes, synthetic URLs; no fetch or wheel integrity claim.",
    ),
    case(
        "python-pylock-variant-complete",
        "python",
        {
            "pylock.dev.toml": 'lock-version="1.0"\ncreated-by="fixture"\n[[packages]]\nname="pytest"\nversion="8.3.3"\n'
            'wheels=[{name="pytest-8.3.3-py3-none-any.whl",url="https://packages.invalid/pytest.whl",hashes={sha256="'
            + "c" * 64
            + '"}}]\n'
        },
        ["pypi:pytest@8.3.3"],
        note="Filename variant with complete structural source; synthetic hash/URL.",
    ),
    case(
        "node-npm-complete",
        "node",
        {
            "package.json": json.dumps({"name": "fixture", "version": "1.0.0", "dependencies": {"debug": "^4.3.7"}}),
            "package-lock.json": json.dumps(
                {
                    "name": "fixture",
                    "version": "1.0.0",
                    "lockfileVersion": 3,
                    "requires": True,
                    "packages": {
                        "": {"name": "fixture", "version": "1.0.0", "dependencies": {"debug": "^4.3.7"}},
                        "node_modules/debug": {
                            "version": "4.3.7",
                            "resolved": "https://packages.invalid/debug.tgz",
                            "dependencies": {"ms": "^2.1.3"},
                        },
                        "node_modules/ms": {"version": "2.1.3", "resolved": "https://packages.invalid/ms.tgz"},
                    },
                }
            ),
        },
        ["npm:debug@4.3.7", "npm:ms@2.1.3"],
        edges=[["npm:debug@4.3.7", "npm:ms@2.1.3"]],
        note="Paired manifest/lock with first-party root. Synthetic registry sources, never resolved online.",
    ),
]

if __package__:
    from .oracle import enrich
else:
    from oracle import enrich

for fixture in CORPUS:
    enrich(fixture)

VERSION = "m046-corpus-v2"
