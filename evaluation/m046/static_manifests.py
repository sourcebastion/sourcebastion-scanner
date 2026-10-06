"""Typed Python manifest parser experiment; no source execution or resolution.

Only PEP 621, literal setup.cfg and a conservative static setup.py AST subset
are admitted. These declarations are not a resolved installation or lock graph.
"""

import ast
import configparser
from dataclasses import dataclass
import hashlib
import io
import re
import time
import tokenize
import tomllib

from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version

from .static_inputs import InputRefusal, relative_path
from .static_requirements import MAX_LOGICAL_LINE, parse_requirement

VERSION = "m046-static-python-manifests-v1"
MAX_RECORDS = 100000
MAX_NESTING = 32
MAX_TOKENS = 100000
NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
PROJECT_KEYS = {
    "name",
    "version",
    "description",
    "readme",
    "requires-python",
    "license",
    "license-files",
    "authors",
    "maintainers",
    "keywords",
    "classifiers",
    "urls",
    "scripts",
    "gui-scripts",
    "entry-points",
    "dependencies",
    "optional-dependencies",
    "import-names",
    "import-namespaces",
    "dynamic",
}
# Only known metadata/non-dependency keys may coexist with the admitted PEP621
# declarations. Unknown keys in recognized dependency tools remain visible;
# new resolver/environment controls must not silently bypass this registry.
TOOL_METADATA_KEYS = {
    "poetry": {
        "name",
        "version",
        "description",
        "authors",
        "maintainers",
        "readme",
        "license",
        "homepage",
        "repository",
        "documentation",
        "keywords",
        "classifiers",
        "package-mode",
        "packages",
        "include",
        "exclude",
    },
    "pdm": {"distribution"},
    "uv": {"cache-dir", "no-cache", "offline", "compile-bytecode", "link-mode"},
    "setuptools": {
        "packages",
        "package-dir",
        "py-modules",
        "include-package-data",
        "package-data",
        "exclude-package-data",
        "zip-safe",
        "license-files",
    },
    "hatch": {},
    "rye": {"managed", "virtual"},
    "pixi": {},
}


@dataclass(frozen=True)
class Declaration:
    requirement: object
    locator: str
    scope: str


@dataclass(frozen=True)
class Manifest:
    path: str
    format: str
    sha256: str
    disposition: str
    reason: str
    declarations: tuple = ()
    application: str | None = None
    environment: tuple = ()
    parser: str = VERSION


class Parser:
    def __init__(self, deadline, max_records):
        self.deadline = deadline
        self.max_records = max_records
        self.records = []
        self.environment = []
        self.application = None

    def check(self):
        if time.monotonic() > self.deadline:
            raise InputRefusal("input-deadline-exceeded")

    def text(self, value):
        self.check()
        if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_LOGICAL_LINE:
            raise InputRefusal("invalid-manifest-value")
        return value

    def add(self, value, locator, scope):
        if len(self.records) >= self.max_records:
            raise InputRefusal("manifest-record-budget-exceeded")
        record = parse_requirement(0, self.text(value))
        if record.direct_reference or record.hashes:
            raise InputRefusal("unsupported-manifest-reference")
        self.records.append(Declaration(record, locator, scope))

    def dependencies(self, values, locator, scope):
        if not isinstance(values, list):
            raise InputRefusal("invalid-manifest-dependencies")
        for index, value in enumerate(values):
            self.add(value, f"{locator}[{index}]", scope)

    def group(self, value):
        value = self.text(value)
        if not NAME.fullmatch(value):
            raise InputRefusal("invalid-manifest-group")
        return canonicalize_name(value)

    def app(self, name, version):
        if name is not None:
            name = self.text(name)
            if not NAME.fullmatch(name):
                raise InputRefusal("invalid-manifest-name")
        if version is None:
            return
        version = self.text(version)
        if version.lstrip().startswith(("file:", "attr:")):
            raise InputRefusal("unsupported-manifest-reference")
        if re.search(r"\d{129,}", version):
            raise InputRefusal("requirement-complexity-budget-exceeded")
        try:
            Version(version)
        except ValueError:
            raise InputRefusal("invalid-manifest-version")
        if name is not None:
            self.application = f"pypi:{canonicalize_name(name)}@{version}"

    def compatibility(self, value, locator):
        value = self.text(value)
        if re.search(r"\d{129,}", value):
            raise InputRefusal("requirement-complexity-budget-exceeded")
        try:
            SpecifierSet(value)
        except ValueError:
            raise InputRefusal("invalid-python-compatibility") from None
        self.environment.append((locator, value))

    def pyproject(self, data):
        self.check()
        project = data.get("project", {})
        if not isinstance(project, dict):
            raise InputRefusal("invalid-project-metadata")
        dynamic = project.get("dynamic", [])
        if not isinstance(dynamic, list) or any(not isinstance(value, str) for value in dynamic):
            raise InputRefusal("invalid-dynamic-metadata")
        if len(set(dynamic)) != len(dynamic) or any(key not in PROJECT_KEYS - {"dynamic"} for key in dynamic):
            raise InputRefusal("invalid-dynamic-metadata")
        if any(
            key in dynamic for key in ("dependencies", "optional-dependencies", "requires-python", "name", "version")
        ):
            raise InputRefusal("unsupported-dynamic-metadata")
        if any(key in project for key in dynamic):
            raise InputRefusal("invalid-dynamic-metadata")
        if "project" in data and ("name" not in project or "version" not in project):
            raise InputRefusal("invalid-project-metadata")
        tool = data.get("tool", {})
        if not isinstance(tool, dict):
            raise InputRefusal("invalid-tool-metadata")
        if not project and any(name in tool for name in ("poetry", "pdm", "setuptools")):
            raise InputRefusal("unsupported-project-metadata")
        for name, metadata_keys in TOOL_METADATA_KEYS.items():
            options = tool.get(name, {})
            if not isinstance(options, dict):
                raise InputRefusal("invalid-tool-metadata")
            if any(key not in metadata_keys for key in options):
                raise InputRefusal("unsupported-tool-dependencies")
        self.dependencies(project.get("dependencies", []), "project.dependencies", "runtime")
        optional = project.get("optional-dependencies", {})
        if not isinstance(optional, dict):
            raise InputRefusal("invalid-manifest-groups")
        names = set()
        for original, dependencies in optional.items():
            group = self.group(original)
            if group in names:
                raise InputRefusal("duplicate-manifest-group")
            names.add(group)
            self.dependencies(dependencies, f"project.optional-dependencies.{original}", "optional:" + group)
        build = data.get("build-system", {})
        if not isinstance(build, dict):
            raise InputRefusal("invalid-build-metadata")
        if "build-system" in data and "requires" not in build:
            raise InputRefusal("invalid-build-metadata")
        self.dependencies(build.get("requires", []), "build-system.requires", "build")
        if "dependency-groups" in data:
            # Typed group expansion needs its own cycle/provenance contract.
            raise InputRefusal("unsupported-dependency-groups")
        if "requires-python" in project:
            self.compatibility(project["requires-python"], "project.requires-python")
        self.app(project.get("name"), project.get("version"))

    def cfg_list(self, value):
        self.check()
        if not isinstance(value, str):
            raise InputRefusal("invalid-manifest-value")
        if value.lstrip().startswith(("file:", "attr:")):
            raise InputRefusal("unsupported-manifest-reference")
        if "%(" in value:
            raise InputRefusal("unsupported-cfg-interpolation")
        # Setuptools list-semi: multiline entries retain PEP508 markers;
        # one-line entries are semicolon-separated dependency declarations.
        entries = value.splitlines()
        if "\n" not in value:
            return [item.strip() for item in value.split(";") if item.strip()]
        return [item.strip() for item in entries if item.strip() and not item.lstrip().startswith("#")]

    def setup_cfg(self, text):
        configuration = configparser.ConfigParser(interpolation=None, strict=True)
        configuration.optionxform = str
        configuration.read_string(text)
        if configuration.defaults():
            # Inherited options need provenance and interpolation semantics,
            # not locators that claim they appeared in each target section.
            raise InputRefusal("unsupported-cfg-defaults")

        def fields(section):
            result = {}
            if configuration.has_section(section):
                for original, value in configuration.items(section):
                    key = original.replace("-", "_").lower()
                    if key in result:
                        raise InputRefusal("duplicate-cfg-option")
                    result[key] = (original, value)
            return result

        options, metadata = fields("options"), fields("metadata")
        if "extras_require" in options or "dependency_links" in options:
            raise InputRefusal("unsupported-cfg-option")
        for field, scope in (("install_requires", "runtime"), ("setup_requires", "build"), ("tests_require", "test")):
            if field in options:
                original, value = options[field]
                self.dependencies(self.cfg_list(value), "options." + original, scope)
        if configuration.has_section("options.extras_require"):
            groups = set()
            for original, value in configuration.items("options.extras_require"):
                group = self.group(original)
                if group in groups:
                    raise InputRefusal("duplicate-manifest-group")
                groups.add(group)
                self.dependencies(self.cfg_list(value), "options.extras_require." + original, "optional:" + group)
        if "python_requires" in options:
            original, value = options["python_requires"]
            self.compatibility(value, "options." + original)
        self.app(
            metadata.get("name", (None, None))[1],
            metadata.get("version", (None, None))[1],
        )

    def setup_ast(self, text):
        # Token admission precedes AST allocation; Python's source recursion
        # limits are not used as configurable inventory budgets.
        depth = 0
        for count, token in enumerate(tokenize.generate_tokens(io.StringIO(text).readline), 1):
            self.check()
            if count > MAX_TOKENS:
                raise InputRefusal("manifest-token-budget-exceeded")
            if token.type == tokenize.OP:
                if token.string in {"(", "[", "{"}:
                    depth += 1
                    if depth > MAX_NESTING:
                        raise InputRefusal("manifest-nesting-budget-exceeded")
                elif token.string in {")", "]", "}"}:
                    depth -= 1
        tree = ast.parse(text)
        aliases, literal_values, calls, imported = set(), {}, [], set()

        def bind(name, alias):
            # Imports can overwrite both callable and literal bindings. The
            # admitted subset refuses rebinding rather than retaining stale
            # setup aliases or constants across import statements.
            if name in imported or name in literal_values:
                raise InputRefusal("dynamic-metadata")
            imported.add(name)
            aliases.add(alias)

        def value(node, depth=0):
            self.check()
            if depth > MAX_NESTING:
                raise InputRefusal("manifest-nesting-budget-exceeded")
            if isinstance(node, ast.Constant) and isinstance(node.value, (str, bool, int, type(None))):
                return node.value
            if isinstance(node, ast.Name) and node.id in literal_values:
                return literal_values[node.id]
            if isinstance(node, (ast.List, ast.Tuple)):
                return [value(item, depth + 1) for item in node.elts]
            if isinstance(node, ast.Dict) and all(key is not None for key in node.keys):
                result = {}
                for key, item in zip(node.keys, node.values):
                    decoded = value(key, depth + 1)
                    if not isinstance(decoded, str) or decoded in result:
                        raise InputRefusal("invalid-literal-metadata")
                    result[decoded] = value(item, depth + 1)
                return result
            raise InputRefusal("dynamic-metadata")

        def function(node):
            if isinstance(node, ast.Name):
                return node.id
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                return node.value.id + "." + node.attr
            return None

        for statement in tree.body:
            self.check()
            if (
                isinstance(statement, ast.ImportFrom)
                and statement.level == 0
                and statement.module in {"setuptools", "distutils.core"}
            ):
                for item in statement.names:
                    if item.name != "setup":
                        raise InputRefusal("dynamic-metadata")
                    bind(item.asname or item.name, item.asname or item.name)
            elif isinstance(statement, ast.Import) and all(item.name == "setuptools" for item in statement.names):
                for item in statement.names:
                    name = item.asname or item.name
                    bind(name, name + ".setup")
            elif (
                isinstance(statement, ast.Assign)
                and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
            ):
                name = statement.targets[0].id
                if name in aliases or name + ".setup" in aliases:
                    raise InputRefusal("dynamic-metadata")
                literal_values[name] = value(statement.value)
            elif (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
            ):
                continue
            elif (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Call)
                and function(statement.value.func) in aliases
            ):
                if statement.value.args:
                    raise InputRefusal("dynamic-metadata")
                fields = {}
                for keyword in statement.value.keywords:
                    if keyword.arg is None or keyword.arg in fields:
                        raise InputRefusal("dynamic-metadata")
                    fields[keyword.arg] = value(keyword.value)
                calls.append(fields)
            else:
                raise InputRefusal("dynamic-metadata")
        if len(calls) != 1:
            raise InputRefusal("dynamic-metadata")
        fields = calls[0]
        for field, scope in (("install_requires", "runtime"), ("setup_requires", "build"), ("tests_require", "test")):
            self.dependencies(fields.get(field, []), "setup." + field, scope)
        extras = fields.get("extras_require", {})
        if not isinstance(extras, dict):
            raise InputRefusal("invalid-manifest-groups")
        groups = set()
        for original, dependencies in extras.items():
            group = self.group(original)
            if group in groups:
                raise InputRefusal("duplicate-manifest-group")
            groups.add(group)
            self.dependencies(dependencies, "setup.extras_require." + original, "optional:" + group)
        if "python_requires" in fields:
            self.compatibility(fields["python_requires"], "setup.python_requires")
        self.app(fields.get("name"), fields.get("version"))


def parse(path, content, fmt, *, deadline=None, max_records=MAX_RECORDS):
    path = relative_path(path)
    if fmt not in {"pep621", "setup-cfg", "setup-python-static"}:
        raise ValueError("unsupported-manifest-parser")
    if not isinstance(content, bytes):
        raise TypeError("manifest parser requires exact bytes")
    if len(content) > 2 * 1024 * 1024:
        raise InputRefusal("input-file-budget-exceeded")
    if isinstance(max_records, bool) or not isinstance(max_records, int) or not 0 <= max_records <= MAX_RECORDS:
        raise ValueError("invalid-parser-record-limit")
    parser = Parser(deadline if deadline is not None else time.monotonic() + 150, max_records)
    sha256 = hashlib.sha256(content).hexdigest()
    try:
        text = content.decode("utf-8-sig")
        parser.check()
        if fmt == "pep621":
            parser.pyproject(tomllib.loads(text))
        elif fmt == "setup-cfg":
            parser.setup_cfg(text)
        else:
            parser.setup_ast(text)
        parser.check()
        return Manifest(
            path,
            fmt,
            sha256,
            "parsed",
            "static-input",
            tuple(parser.records),
            parser.application,
            tuple(parser.environment),
        )
    except InputRefusal as refusal:
        reason = refusal.reason
    except UnicodeDecodeError:
        reason = "invalid-input-encoding"
    except (ValueError, SyntaxError, configparser.Error, tokenize.TokenError, RecursionError):
        reason = "invalid-manifest-syntax"
    disposition = (
        "budget-exceeded"
        if "budget" in reason or "deadline" in reason
        else ("unsupported" if reason.startswith("unsupported-") or reason == "dynamic-metadata" else "malformed")
    )
    return Manifest(path, fmt, sha256, disposition, reason)
