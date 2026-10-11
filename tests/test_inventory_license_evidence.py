"""M048 S03: license observations from inputs the adapters already read."""

import json

import pytest

from sourcebastion.inventory.compose_source import compose_source
from sourcebastion.inventory.contract import INVENTORY_V1, INVENTORY_V2, Producer, canonical_bytes
from sourcebastion.inventory.inputs import Source
from sourcebastion.inventory.licenses import stated_value
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256
from sourcebastion.inventory.secondary_locks import composer_license
from sourcebastion.license_expression import SPDX_LICENSE_LIST_VERSION


def run(root, *, licenses=True):
    config = DiscoveryConfig()
    with Source(root) as source:
        return compose_source(
            source,
            source_sha256="a" * 64,
            producer=Producer(
                name="test",
                version="1",
                code_sha256="a" * 64,
                registry_sha256=REGISTRY_SHA256,
                config_sha256=config.sha256,
            ),
            licenses=licenses,
        )


def composer_lock(*packages):
    return json.dumps({"content-hash": "a" * 32, "packages": list(packages), "packages-dev": []})


def by_name(inventory):
    names = {row.id: row.name for row in inventory.occurrences}
    observed, gaps = {}, {}
    for row in inventory.licenses:
        observed.setdefault(names[row.occurrence_id], []).append(row)
    for row in inventory.license_gaps:
        gaps[names[row.occurrence_id]] = row.reason
    return observed, gaps


def metadata(path, name, version, *headers):
    directory = path / f"site-packages/{name}-{version}.dist-info"
    directory.mkdir(parents=True)
    lines = ["Metadata-Version: 2.4", f"Name: {name}", f"Version: {version}", *headers]
    (directory / "METADATA").write_text("\n".join(lines) + "\n\n")


class TestComposer:
    def test_license_arrays_are_disjunctive_claims(self, tmp_path):
        (tmp_path / "composer.lock").write_text(
            composer_lock(
                {"name": "psr/log", "version": "3.0.2", "type": "library", "license": ["MIT"]},
                {"name": "a/dual", "version": "1.0.0", "license": ["MIT", "GPL-3.0-or-later"]},
                {"name": "a/none", "version": "1.0.0"},
                {"name": "a/free", "version": "1.0.0", "license": ["proprietary"]},
            )
        )
        result = run(tmp_path)
        observed, gaps = by_name(result)
        assert result.schema_version == INVENTORY_V2
        assert result.license_list_version == SPDX_LICENSE_LIST_VERSION
        assert [(o.expression, o.parse, o.evidence) for o in observed["psr/log"]] == [
            ("MIT", "canonical", "lock-record")
        ]
        assert observed["psr/log"][0].source.locator == "/packages/0/license"
        assert observed["a/dual"][0].expression == "MIT OR GPL-3.0-or-later"
        assert (observed["a/free"][0].value_raw, observed["a/free"][0].parse) == ("proprietary", "unparsed")
        assert gaps == {"a/none": "composer-locked-input-states-no-license"}

    def test_members_keep_their_own_precedence(self):
        assert composer_license(["LGPL-2.1-only or GPL-3.0-or-later", "MIT"]) == (
            "(LGPL-2.1-only or GPL-3.0-or-later) OR MIT"
        )
        assert composer_license([]) is None
        assert composer_license("MIT") == "MIT"


class TestPythonMetadata:
    def test_pep639_expression_supersedes_other_claims(self, tmp_path):
        metadata(
            tmp_path,
            "six",
            "1.0.0",
            "License-Expression: MIT OR Apache-2.0",
            "Classifier: License :: OSI Approved :: MIT License",
        )
        observed, gaps = by_name(run(tmp_path))
        assert [(o.expression, o.evidence, o.source.locator) for o in observed["six"]] == [
            ("MIT OR Apache-2.0", "package-metadata", "header:License-Expression[0]")
        ]
        assert gaps == {}

    def test_legacy_license_and_classifiers_are_unparsed_claims(self, tmp_path):
        metadata(tmp_path, "old", "1.0.0", "License: BSD-like")
        metadata(
            tmp_path,
            "classified",
            "2.0.0",
            "Classifier: Programming Language :: Python",
            "Classifier: License :: OSI Approved :: MIT License",
        )
        metadata(tmp_path, "silent", "3.0.0", "License: UNKNOWN")
        result = run(tmp_path)
        observed, gaps = by_name(result)
        assert [(o.value_raw, o.parse) for o in observed["old"]] == [("BSD-like", "unparsed")]
        assert [(o.value_raw, o.parse, o.source.locator) for o in observed["classified"]] == [
            ("License :: OSI Approved :: MIT License", "unparsed", "header:Classifier[1]")
        ]
        assert gaps["silent"] == "pypi-installed-input-states-no-license"


class TestNpm:
    def test_lock_entries_keep_their_stated_license(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({"name": "app", "dependencies": {"a": "1.0.0", "b": "1.0.0"}}))
        (tmp_path / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "app", "dependencies": {"a": "1.0.0", "b": "1.0.0", "c": "1.0.0"}},
                        "node_modules/a": {"version": "1.0.0", "license": "(MIT OR Apache-2.0)"},
                        "node_modules/b": {"version": "1.0.0", "license": {"type": "MIT"}},
                        "node_modules/c": {"version": "1.0.0"},
                    },
                }
            )
        )
        result = run(tmp_path)
        if "npm-selector-runtime-unavailable" in result.coverage.refusal_codes:
            pytest.skip("npm selector runtime needs Linux /proc; covered in CI")
        observed, gaps = by_name(result)
        assert [(o.expression, o.source.locator) for o in observed["a"]] == [
            ("(MIT OR Apache-2.0)", "/packages/node_modules~1a/license")
        ]
        assert [(o.value_raw, o.parse) for o in observed["b"]] == [('{"type":"MIT"}', "unparsed")]
        assert "c" in gaps


    def test_parser_carries_the_stated_value_and_locator(self):
        from sourcebastion.inventory import npm_sources

        lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app"},
                "node_modules/@s/a": {"version": "1.0.0", "license": "MIT"},
                "node_modules/c": {"version": "1.0.0"},
            },
        }
        document = npm_sources.parse(
            json.dumps(lock).encode(), "npm-lock", deadline=float("inf"), check=lambda: None
        )
        licenses = {row.name: row.license for row in document.packages}
        assert licenses == {"@s/a": ("/packages/node_modules~1@s~1a/license", "MIT"), "c": None}


class TestVersions:
    def test_without_the_flag_producers_still_emit_v1(self, tmp_path):
        (tmp_path / "composer.lock").write_text(
            composer_lock({"name": "psr/log", "version": "3.0.2", "license": ["MIT"]})
        )
        result = run(tmp_path, licenses=False)
        assert result.schema_version == INVENTORY_V1
        assert "licenses" not in json.loads(canonical_bytes(result))

    def test_every_occurrence_is_assessed_and_bytes_are_deterministic(self, tmp_path):
        (tmp_path / "composer.lock").write_text(
            composer_lock({"name": "psr/log", "version": "3.0.2", "license": ["MIT"]})
        )
        (tmp_path / "Gemfile.lock").write_text(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.1.7)\n\n"
            "PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack\n\nBUNDLED WITH\n   2.5.19\n"
        )
        result = run(tmp_path)
        observed, gaps = by_name(result)
        assert set(observed) | set(gaps) == {row.name for row in result.occurrences}
        assert gaps["rack"] == "gem-locked-input-states-no-license"
        assert canonical_bytes(run(tmp_path)) == canonical_bytes(result)


class TestStatedValue:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("MIT", "MIT"),
            ("  MIT\n  OR\tISC ", "MIT OR ISC"),
            ({"type": "MIT", "url": "https://x"}, '{"type":"MIT","url":"https://x"}'),
            ("", None),
            (None, None),
            ("x" * 16385, None),
        ],
    )
    def test_values_are_bounded_text_or_nothing(self, value, expected):
        assert stated_value(value) == expected
