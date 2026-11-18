"""M066 S01/T02: source profile from a path list, aggregates only."""

import json

import pytest
from click.testing import CliRunner

from sourcebastion import source_profile as sp
from sourcebastion.cli import main

CORPUS = [
    "go.mod",
    "go.sum",
    "cmd/server/main.go",
    "pkg/api/handler.go",
    "pkg/api/handler_test.go",
    "pkg/api/types.pb.go",
    "pkg/apis/zz_generated.deepcopy.go",
    "vendor/github.com/x/y/lib.go",
    "web/package.json",
    "web/src/App.tsx",
    "web/src/App.test.tsx",
    "web/node_modules/left-pad/index.js",
    "web/dist/app.min.js",
    "docs/index.md",
    "examples/demo/main.py",
    "README.md",
    "requirements-dev.txt",
    "deploy/Dockerfile",
    "deploy/Dockerfile.worker",
    "deploy/chart/Chart.yaml",
    "deploy/chart/templates/service.yaml",
    "infra/main.tf",
    "docker-compose.yml",
    "LICENSE",
]


def _profile(paths):
    return sp.profile(paths)


def test_corpus_classification_is_exact():
    result = _profile(CORPUS)
    assert result["status"] == "ok"
    assert result["path_count"] == len(CORPUS)
    assert result["languages"] == {"go": 6, "python": 1, "javascript": 2, "typescript": 2}
    assert result["infrastructure"] == {
        "compose": 1,
        "dockerfile": 2,
        "helm": 1,
        "terraform": 1,
        "yaml-candidate": 1,
    }
    assert result["path_classes"] == {
        "production": 14,
        "vendored": 2,
        "generated": 3,
        "test": 2,
        "docs": 3,
    }
    assert result["manifest_types"] == ["go-mod", "go-sum", "npm-manifest", "pip-requirements"]
    assert result["ecosystems"] == ["golang", "npm", "pypi"]
    assert sum(result["path_classes"].values()) == len(CORPUS)


@pytest.mark.parametrize(
    "path, expected",
    [
        ("vendor/tests/a_test.go", "vendored"),  # vendored wins over test
        ("tests/generated/x.go", "generated"),  # generated wins over test
        ("docs/tests/x.py", "test"),  # test wins over docs
        ("src/Testimony.java", "production"),  # a name merely starting with Test
        ("src/contest/x.go", "production"),  # "test" inside a directory name
        ("TESTS/x.go", "test"),  # directory names match case-insensitively
    ],
)
def test_path_class_precedence(path, expected):
    assert sp.path_class(path, sp.load_table()) == expected


def test_yaml_is_only_a_candidate():
    result = _profile(["k8s/deployment.yaml", "cfn/stack.yml", ".github/workflows/ci.yml"])
    assert result["infrastructure"] == {"yaml-candidate": 3}
    assert "kubernetes" not in json.dumps(result)


def test_no_input_path_or_name_appears_in_the_output():
    marker = "zqxmarker"
    paths = [
        f"{marker}dir/{marker}file.go",
        f"secret-{marker}/config.{marker}",
        f"{marker}.tf",
        f"vendor/{marker}/a.js",
    ]
    rendered = json.dumps(_profile(paths))
    assert marker not in rendered
    vocabulary = sp.load_table()
    result = _profile(paths)
    assert set(result["languages"]) <= vocabulary.languages
    assert set(result["infrastructure"]) <= vocabulary.infrastructure
    assert set(result["path_classes"]) == set(sp.PATH_CLASSES)
    assert set(result["manifest_types"]) <= vocabulary.manifest_types


def test_nul_delimited_bytes_are_parsed_as_untrusted():
    data = b"a.go\0dir with space/b.py\0\0weird\xff\xfe.rs\0"
    result = sp.profile_bytes(data)
    assert result["path_count"] == 3
    assert result["languages"] == {"go": 1, "python": 1, "rust": 1}


@pytest.mark.parametrize(
    "data, status",
    [
        (b"/etc/passwd\0", "invalid_path"),
        (b"a\nb.go\0", "invalid_path"),
        (b"x" * (sp.MAX_PATH_BYTES + 1), "invalid_path"),
    ],
)
def test_bad_paths_stop_with_a_fixed_status(data, status):
    result = sp.profile_bytes(data)
    assert result["status"] == status
    assert "path_count" not in result
    assert "passwd" not in json.dumps(result)


def test_too_many_paths_stops_rather_than_counting_part(monkeypatch):
    monkeypatch.setattr(sp, "MAX_PATHS", 3)
    result = sp.profile_bytes(b"a.go\0b.go\0c.go\0d.go\0")
    assert result["status"] == "too_large"
    assert "languages" not in result


def test_oversized_input_is_refused(monkeypatch):
    monkeypatch.setattr(sp, "MAX_INPUT_BYTES", 8)
    assert sp.profile_bytes(b"a.go\0b.go\0c.go\0")["status"] == "too_large"


def test_table_identity_is_versioned_and_stable():
    table = sp.load_table()
    assert table.version == "sourcebastion.source-profile-table/1"
    assert len(table.sha256) == 64
    result = _profile(["a.go"])
    assert result["table_version"] == table.version
    assert result["table_sha256"] == table.sha256
    assert result["version"] == sp.PROFILE_VERSION


def test_empty_list_profiles_as_zero():
    result = sp.profile_bytes(b"")
    assert result["status"] == "ok" and result["path_count"] == 0
    assert result["path_classes"] == dict.fromkeys(sp.PATH_CLASSES, 0)


def test_cli_reads_a_file_and_stdin(tmp_path):
    listing = tmp_path / "paths"
    listing.write_bytes(b"\0".join(p.encode() for p in CORPUS) + b"\0")
    runner = CliRunner()
    from_file = runner.invoke(main, ["profile", str(listing)])
    assert from_file.exit_code == 0, from_file.output
    from_stdin = runner.invoke(main, ["profile", "-"], input=listing.read_bytes())
    assert from_stdin.exit_code == 0
    assert json.loads(from_file.output) == json.loads(from_stdin.output) == _profile(CORPUS)


def test_cli_exits_nonzero_on_a_refusal():
    result = CliRunner().invoke(main, ["profile", "-"], input=b"/abs\0")
    assert result.exit_code == 2
    assert json.loads(result.output)["status"] == "invalid_path"
