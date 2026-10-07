"""Hand-authored semantic expectations, independent of candidate parsers.

Helpers only assemble records and hash the fixture text. They do not parse inputs
or infer expected packages/edges from any tool output. All roots and locators below
are explicit. A JSON pointer/TOML key is a locator, not an invented line number.
"""

import hashlib


def inp(path, fmt="pip-requirements", disposition="parsed", reason="static-input", root="."):
    return {"path": path, "format": fmt, "roots": [root], "disposition": disposition, "reason": reason}


def occ(
    package,
    path,
    locator="line:1",
    *,
    root=".",
    selection="declared-pin",
    scope="unknown",
    marker=None,
    extras=(),
    declaration=None,
    hashes=(),
    relationship="unknown",
    activation=None,
    requires_python=None,
):
    return {
        "package": package,
        "path": path,
        "locator": locator,
        "root": root,
        "selection": selection,
        "scope": scope,
        "marker": marker,
        "extras": list(extras),
        "declared_range": declaration,
        "hashes": list(hashes),
        "relationship": relationship,
        "requires_python": requires_python,
        "activation": activation
        or ("unknown" if marker or requires_python or scope.startswith("optional:") else "unconditional"),
    }


def pin(package, path, locator="line:1", **kwargs):
    return occ(package, path, locator, declaration="==" + package.rsplit("@", 1)[1], **kwargs)


def locked(package, path, locator, **kwargs):
    return occ(package, path, locator, selection="locked", scope="unknown", relationship="unknown", **kwargs)


def rel(kind, path, target, locator="line:1", root="."):
    return {"kind": kind, "path": path, "target": target, "locator": locator, "root": root}


def edge(parent, child, path, locator, root="."):
    return {"parent": parent, "child": child, "path": path, "locator": locator, "root": root, "kind": "dependency"}


def declaration(name, value, path, locator, **kwargs):
    return {
        "name": name,
        "range": value,
        "path": path,
        "locator": locator,
        "root": kwargs.get("root", "."),
        "scope": kwargs.get("scope", "unknown"),
        "marker": kwargs.get("marker"),
        "extras": kwargs.get("extras", []),
        "classification": kwargs.get("classification", "unknown"),
    }


# Inputs, occurrences, relationships, declarations and source references are
# intentionally enumerated. A missing case is an error, never a guessed oracle.
SEMANTICS = {
    "python-requirements": ([inp("requirements.txt")], [pin("pypi:requests@2.32.3", "requirements.txt")]),
    "python-input": ([inp("requirements.in")], [pin("pypi:requests@2.32.3", "requirements.in")]),
    "python-custom-input": ([inp("deploy.in")], [pin("pypi:flask@3.0.3", "deploy.in")]),
    "python-custom-hashed-lock": (
        [inp("dependencies-prod.txt")],
        [pin("pypi:requests@2.32.3", "dependencies-prod.txt", hashes=["sha256:" + "a" * 64])],
    ),
    "python-hidden": (
        [inp(".deps/requirements.txt", root=".deps")],
        [pin("pypi:urllib3@2.2.2", ".deps/requirements.txt", root=".deps")],
    ),
    "python-include": (
        [inp("requirements.txt"), inp("locks/base.txt")],
        [pin("pypi:requests@2.32.3", "locks/base.txt")],
    ),
    "python-constraint-only": (
        [
            inp("requirements.txt", disposition="declaration-only", reason="no-required-package"),
            inp("constraints.txt", disposition="declaration-only", reason="constraint-only"),
        ],
        [],
    ),
    "python-constraint-resolves": (
        [inp("requirements.txt"), inp("constraints.txt", disposition="declaration-only", reason="constraint-only")],
        [occ("pypi:requests@2.32.3", "requirements.txt", selection="constrained", declaration="")],
    ),
    "python-marker": (
        [inp("requirements.txt")],
        [pin("pypi:requests@2.32.3", "requirements.txt", marker='python_version < "3.12"')],
    ),
    "python-extras": ([inp("requirements.txt")], [pin("pypi:requests@2.32.3", "requirements.txt", extras=["socks"])]),
    "python-range": ([inp("requirements.txt", disposition="declaration-only", reason="no-selected-version")], []),
    "python-normalization": ([inp("requirements.txt")], [pin("pypi:typing-extensions@4.12.2", "requirements.txt")]),
    "python-conflicting-roots": (
        [inp("a/requirements.txt", root="a"), inp("b/requirements.txt", root="b")],
        [
            pin("pypi:requests@2.31.0", "a/requirements.txt", root="a"),
            pin("pypi:requests@2.32.3", "b/requirements.txt", root="b"),
        ],
    ),
    "python-pyproject": (
        [inp("pyproject.toml", "pep621")],
        [
            pin(
                "pypi:requests@2.32.3",
                "pyproject.toml",
                "project.dependencies[0]",
                scope="runtime",
                relationship="direct",
            )
        ],
    ),
    "python-pyproject-optional": (
        [inp("pyproject.toml", "pep621")],
        [
            pin(
                "pypi:pytest@8.3.3",
                "pyproject.toml",
                "project.optional-dependencies.test[0]",
                scope="optional:test",
                relationship="direct",
            )
        ],
    ),
    "python-setup-cfg": (
        [inp("setup.cfg", "setup-cfg")],
        [
            pin(
                "pypi:requests@2.32.3",
                "setup.cfg",
                "options.install_requires[0]",
                scope="runtime",
                relationship="direct",
            )
        ],
    ),
    "python-static-setup": (
        [inp("setup.py", "setup-python-static")],
        [pin("pypi:requests@2.32.3", "setup.py", "setup.install_requires[0]", scope="runtime", relationship="direct")],
    ),
    "python-dynamic-setup": ([inp("setup.py", "setup-python-static", "unsupported", "dynamic-metadata")], []),
    "python-pipfile": (
        [inp("Pipfile.lock", "pipfile-lock", "unsupported", "missing-lock-metadata")],
        [
            occ(
                "pypi:requests@2.32.3",
                "Pipfile.lock",
                "/default/requests",
                selection="locked",
                declaration="==2.32.3",
                relationship="unknown",
                activation="unknown",
            ),
            occ(
                "pypi:pytest@8.3.3",
                "Pipfile.lock",
                "/develop/pytest",
                selection="locked",
                scope="development",
                declaration="==8.3.3",
                relationship="unknown",
                activation="unknown",
            ),
        ],
    ),
    "python-pipfile-complete": (
        [inp("Pipfile.lock", "pipfile-lock")],
        [
            occ(
                "pypi:requests@2.32.3",
                "Pipfile.lock",
                "/default/requests",
                selection="locked",
                declaration="==2.32.3",
                hashes=["sha256:" + "a" * 64],
                relationship="unknown",
            ),
            occ(
                "pypi:pytest@8.3.3",
                "Pipfile.lock",
                "/develop/pytest",
                selection="locked",
                scope="development",
                declaration="==8.3.3",
                hashes=["sha256:" + "b" * 64],
                relationship="unknown",
            ),
        ],
    ),
    "python-poetry": (
        [inp("poetry.lock", "poetry-lock", "malformed", "invalid-lock-metadata-hash")],
        [],
    ),
    "python-uv": (
        [inp("uv.lock", "uv-lock", "unsupported", "missing-lock-source")],
        [
            {
                **locked("pypi:requests@2.32.3", "uv.lock", "package[0]", activation="unknown"),
                "source_identity": "5a06749b2297be54ac5699f6f2761716adc5001a2d5f8b915ab2172922dd5706",
                "source_kind": "registry-asserted",
                "group": None,
            }
        ],
    ),
    "python-pdm": (
        [inp("pdm.lock", "pdm-lock", "unsupported", "missing-lock-source")],
        [
            {
                **occ(
                    "pypi:requests@2.32.3",
                    "pdm.lock",
                    "package[0].groups[0]",
                    selection="locked",
                    scope="group:default",
                    relationship="unknown",
                    requires_python=">=3.8",
                ),
                "source_identity": None,
                "source_kind": "unknown",
                "group": "default",
            }
        ],
    ),
    "python-pylock": (
        [inp("pylock.toml", "pylock", "unsupported", "missing-lock-source")],
        [locked("pypi:requests@2.32.3", "pylock.toml", "packages[0]")],
    ),
    "python-pylock-variant": (
        [inp("pylock.dev.toml", "pylock", "unsupported", "missing-lock-source")],
        [locked("pypi:pytest@8.3.3", "pylock.dev.toml", "packages[0]")],
    ),
    "python-include-cycle": (
        [
            inp("requirements.txt", disposition="malformed", reason="include-cycle"),
            inp("other.txt", disposition="malformed", reason="include-cycle"),
        ],
        [],
    ),
    "python-include-escape": ([inp("requirements.txt", disposition="unsafe", reason="outside-source")], []),
    "python-malformed": ([inp("requirements.txt", disposition="malformed", reason="invalid-requirement")], []),
    "python-false-positive": ([inp("meeting-notes.txt", "unrecognized", "ignored", "non-dependency-prose")], []),
    "node-npm-v3": (
        [inp("package-lock.json", "npm-lock-v3")],
        [locked("npm:lodash@4.17.21", "package-lock.json", "/packages/node_modules~1lodash")],
    ),
    "node-npm-edges": (
        [inp("package-lock.json", "npm-lock-v3")],
        [
            locked("npm:debug@4.3.7", "package-lock.json", "/packages/node_modules~1debug"),
            locked("npm:ms@2.1.3", "package-lock.json", "/packages/node_modules~1ms"),
        ],
    ),
    "node-npm-dev": (
        [inp("package-lock.json", "npm-lock-v3")],
        [
            occ(
                "npm:mocha@10.7.3",
                "package-lock.json",
                "/packages/node_modules~1mocha",
                selection="locked",
                scope="development",
                relationship="unknown",
            )
        ],
    ),
    "node-npm-nested": (
        [inp("package-lock.json", "npm-lock-v3")],
        [
            locked("npm:ms@2.1.3", "package-lock.json", "/packages/node_modules~1ms"),
            locked("npm:ms@2.0.0", "package-lock.json", "/packages/node_modules~1debug~1node_modules~1ms"),
        ],
    ),
    "node-yarn": ([inp("yarn.lock", "yarn-lock-v1")], [locked("npm:lodash@4.17.21", "yarn.lock", "lodash@^4.17.21")]),
    "node-pnpm": (
        [inp("pnpm-lock.yaml", "pnpm-lock-v9")],
        [
            occ(
                "npm:lodash@4.17.21",
                "pnpm-lock.yaml",
                "packages.lodash@4.17.21",
                selection="locked",
                declaration="^4.17.21",
                scope="runtime",
                relationship="direct",
            )
        ],
    ),
    "node-manifest-range": ([inp("package.json", "npm-manifest", "declaration-only", "no-selected-version")], []),
    "node-malformed": ([inp("package-lock.json", "npm-lock-v3", "malformed", "invalid-json")], []),
    "go-module": ([inp("go.mod", "go-mod", "declaration-only", "unresolved-module-graph")], []),
    "go-indirect": ([inp("go.mod", "go-mod", "declaration-only", "unresolved-module-graph")], []),
    "go-sums-only": ([inp("go.sum", "go-sum", "declaration-only", "historical-checksums")], []),
    "go-local-replacement": ([inp("go.mod", "go-mod", "unsafe", "outside-source-replacement")], []),
    "rust-lock": ([inp("Cargo.lock", "cargo-lock-v3")], [locked("cargo:itoa@1.0.11", "Cargo.lock", "package[0]")]),
    "rust-edges": (
        [inp("Cargo.lock", "cargo-lock-v3")],
        [
            locked("cargo:serde_json@1.0.128", "Cargo.lock", "package[0]"),
            locked("cargo:itoa@1.0.11", "Cargo.lock", "package[1]"),
        ],
    ),
    "rust-conflicting-roots": (
        [inp("a/Cargo.lock", "cargo-lock-v3", root="a"), inp("b/Cargo.lock", "cargo-lock-v3", root="b")],
        [
            locked("cargo:itoa@1.0.11", "a/Cargo.lock", "package[0]", root="a"),
            locked("cargo:itoa@1.0.10", "b/Cargo.lock", "package[0]", root="b"),
        ],
    ),
    "rust-manifest-range": ([inp("Cargo.toml", "cargo-manifest", "declaration-only", "no-selected-version")], []),
    "java-gradle-lock": (
        [inp("gradle.lockfile", "gradle-lock")],
        [
            occ(
                "maven:org.apache.commons/commons-lang3@3.14.0",
                "gradle.lockfile",
                "line:2",
                selection="locked",
                scope="compileClasspath",
                relationship="unknown",
            )
        ],
    ),
    "dotnet-lock": (
        [inp("packages.lock.json", "nuget-lock")],
        [
            occ(
                "nuget:Newtonsoft.Json@13.0.3",
                "packages.lock.json",
                "/dependencies/net8.0/Newtonsoft.Json",
                selection="locked",
                scope="net8.0",
                declaration="[13.0.3, )",
                relationship="direct",
            )
        ],
    ),
    "ruby-lock": (
        [inp("Gemfile.lock", "bundler-lock")],
        [occ("gem:rack@3.1.7", "Gemfile.lock", "GEM.specs.rack", selection="locked", relationship="direct")],
    ),
    "php-lock": (
        [inp("composer.lock", "composer-lock")],
        [occ("composer:psr/log@3.0.2", "composer.lock", "/packages/0", selection="locked", relationship="unknown")],
    ),
    "symlink-escape": ([inp("requirements.txt", "symlink", "unsafe", "outside-source")], []),
    "symlink-cycle": (
        [inp("a", "symlink", "unsafe", "symlink-cycle"), inp("b", "symlink", "unsafe", "symlink-cycle")],
        [],
    ),
    "python-product-build-input": (
        [inp("scripts/python-build.in", root="scripts")],
        [pin("pypi:pip@26.0.1", "scripts/python-build.in", root="scripts")],
    ),
    "python-product-hidden-lock": (
        [inp(".github/python-locks/build.txt", root=".github/python-locks")],
        [
            pin(
                "pypi:pip@26.0.1",
                ".github/python-locks/build.txt",
                root=".github/python-locks",
                hashes=["sha256:" + "b" * 64],
            )
        ],
    ),
    "python-pip-extension": ([inp("dependencies.pip")], [pin("pypi:flask@3.0.3", "dependencies.pip")]),
    "python-long-options": (
        [
            inp("requirements.txt"),
            inp("locks/base.pip"),
            inp("constraints.txt", disposition="declaration-only", reason="constraint-only"),
        ],
        [occ("pypi:requests@2.32.3", "locks/base.pip", selection="constrained", declaration=">=2.31,<3")],
    ),
    "python-conflicting-constraint": (
        [
            inp("requirements.txt", disposition="malformed", reason="constraint-conflict"),
            inp("constraints.txt", disposition="declaration-only", reason="constraint-only"),
        ],
        [],
    ),
    "python-marker-alternatives": (
        [inp("requirements.txt")],
        [
            pin("pypi:requests@2.31.0", "requirements.txt", marker='python_version < "3.12"'),
            pin("pypi:requests@2.32.3", "requirements.txt", "line:2", marker='python_version >= "3.12"'),
        ],
    ),
    "python-identical-multiple-roots": (
        [inp("a/requirements.txt", root="a"), inp("b/requirements.txt", root="b")],
        [
            pin("pypi:requests@2.32.3", "a/requirements.txt", root="a"),
            pin("pypi:requests@2.32.3", "b/requirements.txt", root="b"),
        ],
    ),
    "python-pylock-complete": (
        [inp("pylock.toml", "pylock")],
        [
            locked("pypi:requests@2.32.3", "pylock.toml", "packages[0]", hashes=["sha256:" + "a" * 64]),
            locked("pypi:urllib3@2.2.2", "pylock.toml", "packages[1]", hashes=["sha256:" + "b" * 64]),
        ],
    ),
    "python-pylock-variant-complete": (
        [inp("pylock.dev.toml", "pylock")],
        [locked("pypi:pytest@8.3.3", "pylock.dev.toml", "packages[0]", hashes=["sha256:" + "c" * 64])],
    ),
    "node-npm-complete": (
        [inp("package.json", "npm-manifest"), inp("package-lock.json", "npm-lock-v3")],
        [
            occ(
                "npm:debug@4.3.7",
                "package-lock.json",
                "/packages/node_modules~1debug",
                selection="locked",
                declaration="^4.3.7",
                scope="runtime",
                relationship="direct",
            ),
            occ(
                "npm:ms@2.1.3",
                "package-lock.json",
                "/packages/node_modules~1ms",
                selection="locked",
                relationship="transitive",
                declaration="^2.1.3",
                scope="runtime",
            ),
        ],
    ),
}

REFERENCES = {
    "python-include": [rel("include", "requirements.txt", "locks/base.txt")],
    "python-constraint-only": [rel("constraint", "requirements.txt", "constraints.txt")],
    "python-constraint-resolves": [
        rel("constraint", "requirements.txt", "constraints.txt", "line:2"),
        rel("version-evidence", "requirements.txt", "constraints.txt"),
    ],
    "python-include-cycle": [
        rel("include", "requirements.txt", "other.txt"),
        rel("include", "other.txt", "requirements.txt"),
    ],
    "python-include-escape": [rel("include-refused", "requirements.txt", "../outside.txt")],
    "go-local-replacement": [rel("replacement-refused", "go.mod", "../dependency", "line:5")],
    "python-long-options": [
        rel("include", "requirements.txt", "locks/base.pip"),
        rel("constraint", "requirements.txt", "constraints.txt", "line:2"),
        rel("version-evidence", "locks/base.pip", "constraints.txt"),
    ],
    "python-conflicting-constraint": [rel("constraint", "requirements.txt", "constraints.txt", "line:2")],
}

EDGES = {
    "node-npm-edges": [
        edge("npm:debug@4.3.7", "npm:ms@2.1.3", "package-lock.json", "/packages/node_modules~1debug/dependencies/ms")
    ],
    "rust-edges": [edge("cargo:serde_json@1.0.128", "cargo:itoa@1.0.11", "Cargo.lock", "package[0].dependencies[0]")],
    "python-pylock-complete": [
        edge("pypi:requests@2.32.3", "pypi:urllib3@2.2.2", "pylock.toml", "packages[0].dependencies[0]")
    ],
    "node-npm-complete": [
        edge("npm:debug@4.3.7", "npm:ms@2.1.3", "package-lock.json", "/packages/node_modules~1debug/dependencies/ms")
    ],
}

DECLARATIONS = {
    "go-module": [
        declaration("golang:golang.org/x/text", ">=v0.18.0", "go.mod", "line:5", classification="direct-declared")
    ],
    "go-indirect": [
        declaration("golang:golang.org/x/text", ">=v0.18.0", "go.mod", "line:5", classification="indirect-declared")
    ],
    "python-constraint-only": [declaration("pypi:urllib3", "==2.2.2", "constraints.txt", "line:1", scope="constraint")],
    "python-constraint-resolves": [
        declaration("pypi:requests", "", "requirements.txt", "line:1"),
        declaration("pypi:requests", "==2.32.3", "constraints.txt", "line:1", scope="constraint"),
    ],
    "python-range": [declaration("pypi:requests", ">=2.31,<3", "requirements.txt", "line:1")],
    "node-manifest-range": [
        declaration(
            "npm:lodash",
            "^4.17.21",
            "package.json",
            "/dependencies/lodash",
            scope="runtime",
            classification="direct-declared",
        )
    ],
    "rust-manifest-range": [declaration("cargo:itoa", "1", "Cargo.toml", "dependencies.itoa")],
    "python-long-options": [
        declaration("pypi:requests", ">=2.31,<3", "locks/base.pip", "line:1"),
        declaration("pypi:requests", "==2.32.3", "constraints.txt", "line:1", scope="constraint"),
    ],
    "python-conflicting-constraint": [
        declaration("pypi:requests", "==2.32.3", "requirements.txt", "line:1"),
        declaration("pypi:requests", "<2.32", "constraints.txt", "line:1", scope="constraint"),
    ],
    "node-npm-complete": [
        declaration(
            "npm:debug",
            "^4.3.7",
            "package.json",
            "/dependencies/debug",
            scope="runtime",
            classification="direct-declared",
        )
    ],
}

# First-party roots are explicit, not selected by membership in expected packages.
APPLICATIONS = {
    "python-pyproject": [{"root": ".", "identity": "pypi:fixture@1.0.0", "path": "pyproject.toml"}],
    "python-pyproject-optional": [{"root": ".", "identity": "pypi:fixture@1.0.0", "path": "pyproject.toml"}],
    "node-npm-complete": [{"root": ".", "identity": "npm:fixture@1.0.0", "path": "package.json"}],
    "rust-manifest-range": [{"root": ".", "identity": "cargo:fixture@0.1.0", "path": "Cargo.toml"}],
}

ENVIRONMENTS = {
    "python-poetry": [],
    "python-uv": [
        {
            "root": ".",
            "path": "uv.lock",
            "locator": "requires-python",
            "requires_python": ">=3.12",
            "activation": "unknown",
            "kind": "root",
        }
    ],
    "python-pdm": [
        {
            "root": ".",
            "path": "pdm.lock",
            "locator": "package[0].requires_python",
            "requires_python": ">=3.8",
            "activation": "unknown",
            "kind": "package",
            "package": "pypi:requests@2.32.3",
        }
    ],
}


def registry_occ(
    package,
    path,
    locator,
    *,
    group=None,
    scope="unknown",
    marker=None,
    extras=(),
    hashes=(),
    compatibility=None,
    source=None,
    optional=None,
):
    record = {
        **occ(
            package,
            path,
            locator,
            selection="locked",
            scope=scope,
            marker=marker,
            extras=extras,
            hashes=hashes,
            activation="unknown",
            requires_python=compatibility,
        ),
        "group": group,
        "source_identity": source,
        "source_kind": "registry-asserted" if source else "unknown",
    }
    if path == "poetry.lock":
        record["optional"] = optional
        record["requires_python_dialect"] = "poetry-core-2.1.3"
    return record


def registry_edge(
    path,
    locator,
    parent_locator,
    *,
    group=None,
    scope="unknown",
    constraint=">=1,<2",
    marker=None,
    extras=(),
    source=None,
    dialect="pep440",
    marker_semantics="pep508",
    parent="pypi:parent@1",
    child_locator="package[1]",
):
    record = {
        **edge(parent, "pypi:foo@1", path, locator),
        "parent_locator": parent_locator,
        "child_locator": child_locator,
        "child_source_identity": source,
        "group": group,
        "scope": scope,
        "declared_constraint": constraint,
        "marker": marker,
        "extras": list(extras),
        "constraint_dialect": dialect,
        "marker_semantics": marker_semantics,
        "activation": "unknown",
    }
    if path == "uv.lock":
        record["exact_version"] = None
    return record


def compatibility(path, locator, *, package=None):
    record = {
        "root": ".",
        "path": path,
        "locator": locator,
        "requires_python": ">=3.12",
        "activation": "unknown",
        "kind": "package" if package else "root",
    }
    if package:
        record["package"] = package
    if path == "poetry.lock":
        record["constraint_dialect"] = "poetry-core-2.1.3"
    return record


UV_REGISTRY = "5a06749b2297be54ac5699f6f2761716adc5001a2d5f8b915ab2172922dd5706"
SEMANTICS.update(
    {
        "python-poetry-graph": (
            [inp("poetry.lock", "poetry-lock")],
            [
                registry_occ(
                    "pypi:parent@1",
                    "poetry.lock",
                    "package[0].groups[0]",
                    group="main",
                    scope="group:main",
                    marker='os_name == "posix"',
                    hashes=["sha256:" + "a" * 64],
                    compatibility=">=3.12",
                    optional=False,
                ),
                registry_occ(
                    "pypi:parent@1",
                    "poetry.lock",
                    "package[0].groups[1]",
                    group="test",
                    scope="group:test",
                    hashes=["sha256:" + "a" * 64],
                    compatibility=">=3.12",
                    optional=False,
                ),
                registry_occ(
                    "pypi:foo@1",
                    "poetry.lock",
                    "package[1].groups[0]",
                    group="main",
                    scope="group:main",
                    hashes=["sha256:" + "b" * 64],
                    compatibility=">=3.12",
                    optional=False,
                ),
                registry_occ(
                    "pypi:foo@1",
                    "poetry.lock",
                    "package[1].groups[1]",
                    group="test",
                    scope="group:test",
                    hashes=["sha256:" + "b" * 64],
                    compatibility=">=3.12",
                    optional=False,
                ),
            ],
        ),
        "python-pdm-graph": (
            [inp("pdm.lock", "pdm-lock")],
            [
                registry_occ(
                    "pypi:parent@1",
                    "pdm.lock",
                    "package[0].groups[0]",
                    group="default",
                    scope="group:default",
                    hashes=["sha256:" + "a" * 64],
                    compatibility=">=3.12",
                ),
                registry_occ(
                    "pypi:parent@1",
                    "pdm.lock",
                    "package[0].groups[1]",
                    group="test",
                    scope="group:test",
                    hashes=["sha256:" + "a" * 64],
                    compatibility=">=3.12",
                ),
                registry_occ(
                    "pypi:foo@1",
                    "pdm.lock",
                    "package[1].groups[0]",
                    group="default",
                    scope="group:default",
                    extras=["test"],
                    hashes=["sha256:" + "b" * 64],
                    compatibility=">=3.12",
                ),
                registry_occ(
                    "pypi:foo@1",
                    "pdm.lock",
                    "package[1].groups[1]",
                    group="test",
                    scope="group:test",
                    extras=["test"],
                    hashes=["sha256:" + "b" * 64],
                    compatibility=">=3.12",
                ),
                registry_occ(
                    "pypi:foo@1",
                    "pdm.lock",
                    "package[2].groups[0]",
                    group="default",
                    scope="group:default",
                    hashes=["sha256:" + "b" * 64],
                    compatibility=">=3.12",
                ),
                registry_occ(
                    "pypi:foo@1",
                    "pdm.lock",
                    "package[2].groups[1]",
                    group="test",
                    scope="group:test",
                    hashes=["sha256:" + "b" * 64],
                    compatibility=">=3.12",
                ),
            ],
        ),
        "python-uv-graph": (
            [inp("uv.lock", "uv-lock")],
            [
                registry_occ(
                    "pypi:parent@1", "uv.lock", "package[0]", hashes=["sha256:" + "a" * 64], source=UV_REGISTRY
                ),
                registry_occ("pypi:foo@1", "uv.lock", "package[1]", hashes=["sha256:" + "b" * 64], source=UV_REGISTRY),
            ],
        ),
    }
)
EDGES.update(
    {
        "python-poetry-graph": [
            registry_edge(
                "poetry.lock",
                "package[0].dependencies.foo",
                "package[0].groups[0]",
                group="main",
                scope="group:main",
                dialect="poetry-core-2.1.3",
            ),
            registry_edge(
                "poetry.lock",
                "package[0].dependencies.foo",
                "package[0].groups[1]",
                group="test",
                scope="group:test",
                dialect="poetry-core-2.1.3",
            ),
        ],
        "python-pdm-graph": [
            registry_edge(
                "pdm.lock",
                "package[0].dependencies[0]",
                "package[0].groups[0]",
                group="default",
                scope="group:default",
                extras=["test"],
            ),
            registry_edge(
                "pdm.lock",
                "package[0].dependencies[0]",
                "package[0].groups[1]",
                group="test",
                scope="group:test",
                extras=["test"],
            ),
            registry_edge(
                "pdm.lock",
                "package[1].dependencies[0]",
                "package[1].groups[0]",
                parent="pypi:foo@1",
                child_locator="package[2]",
                group="default",
                scope="group:default",
                constraint="==1",
            ),
            registry_edge(
                "pdm.lock",
                "package[1].dependencies[0]",
                "package[1].groups[1]",
                parent="pypi:foo@1",
                child_locator="package[2]",
                group="test",
                scope="group:test",
                constraint="==1",
            ),
        ],
        "python-uv-graph": [
            registry_edge(
                "uv.lock",
                "package[0].dependencies[0]",
                "package[0]",
                constraint="",
                marker='python_version < "3.14"',
                extras=["test"],
                source=UV_REGISTRY,
                dialect="exact-identity",
                marker_semantics="simplified-relative-to-root-python",
            ),
        ],
    }
)
ENVIRONMENTS.update(
    {
        "python-poetry-graph": [
            compatibility("poetry.lock", "metadata.python-versions"),
            compatibility("poetry.lock", "package[0].python-versions", package="pypi:parent@1"),
            compatibility("poetry.lock", "package[1].python-versions", package="pypi:foo@1"),
        ],
        "python-pdm-graph": [
            compatibility("pdm.lock", "metadata.targets[0].requires_python"),
            compatibility("pdm.lock", "package[0].requires_python", package="pypi:parent@1"),
            compatibility("pdm.lock", "package[1].requires_python", package="pypi:foo@1"),
            compatibility("pdm.lock", "package[2].requires_python", package="pypi:foo@1"),
        ],
        "python-uv-graph": [compatibility("uv.lock", "requires-python")],
    }
)


DIMENSIONS = (
    "inputs",
    "occurrences",
    "relationships",
    "declaration_records",
    "references",
    "roots",
    "applications",
    "environment_records",
    "fidelity",
)


def enrich(fixture):
    inputs, occurrences = SEMANTICS[fixture["id"]]
    expected = fixture["expected"]
    expected["semantic_schema"] = "m046-oracle-v4"
    expected["inputs"] = [
        {
            **record,
            "sha256": (
                hashlib.sha256(fixture["files"][record["path"]].encode()).hexdigest()
                if record["path"] in fixture["files"]
                else None
            ),
        }
        for record in inputs
    ]
    expected["occurrences"] = occurrences
    expected["relationships"] = EDGES.get(fixture["id"], [])
    expected["declaration_records"] = DECLARATIONS.get(fixture["id"], [])
    expected["references"] = REFERENCES.get(fixture["id"], [])
    expected["roots"] = sorted({root for record in inputs for root in record["roots"]})
    expected["applications"] = APPLICATIONS.get(fixture["id"], [])
    expected["environment_records"] = ENVIRONMENTS.get(fixture["id"], [])
    invalid = any(record["disposition"] in {"unsafe", "malformed", "unsupported"} for record in inputs)
    expected["fidelity"] = {
        "discovery": "complete",
        "parsing": "partial" if invalid else "complete",
        "enumeration": "partial" if invalid else "complete",
        "version_selection": "partial" if invalid or expected["declarations"] else "complete",
        "graph": "evidenced-only" if expected["relationships"] else "unknown",
        "environment": (
            "unknown"
            if fixture["id"] == "python-pipfile"
            else (
                "conditional-unknown"
                if any(record["activation"] == "unknown" for record in occurrences)
                else "unconditional"
            )
        ),
    }
