"""Admission boundaries for native combined-cataloger diagnostics."""

from copy import deepcopy
import json

import pytest

from evaluation.m046.syft_native import non_cpe, trace_admission, verify_projection
from evaluation.m046 import syft_native


def test_runtime_threads_are_distinct_from_trusted_interpreter_process():
    trace = "\n".join(
        [
            '1 execve("/trusted/go", [], []) = 0',
            "1 clone(flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND) = 2",
            "1 clone(flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 3",
            '3 execve("/trusted/python", [], []) = 0',
        ]
    )
    assert trace_admission(trace, "/trusted/go", "/trusted/python")["network_attempts"] == 0


def pidfd_trace():
    return "\n".join(
        [
            '1 execve("/trusted/go", [], []) = 0',
            "1 clone(child_stack=NULL, flags=CLONE_VM|CLONE_PIDFD|CLONE_VFORK <unfinished ...>",
            "2 exit_group(0) = ?",
            "1 <... clone resumed>, parent_tid=[12]) = 2",
            "1 waitid(P_PIDFD, 12, {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=2, si_status=0, si_utime=0}, WEXITED|__WCLONE, NULL) = 0",
            "1 clone(child_stack=NULL, flags=CLONE_VM|CLONE_PIDFD|CLONE_VFORK|SIGCHLD) = 3",
            '3 execve("/trusted/python", [], []) = 0',
        ]
    )


def test_exact_exit_only_reaped_go_pidfd_probe_is_reported_separately():
    result = trace_admission(pidfd_trace(), "/trusted/go", "/trusted/python")
    assert result["pidfd_probe_children"] == ["2"]
    assert result["nonthread_process_calls"] == ["clone"]


def test_split_pidfd_waitid_retains_semantics_without_separator_space():
    trace = pidfd_trace().replace(
        "1 waitid(P_PIDFD, 12, {",
        "1 waitid(P_PIDFD, 12,  <unfinished ...>\n1 <... waitid resumed>{",
    )
    assert trace_admission(trace, "/trusted/go", "/trusted/python")["pidfd_probe_children"] == ["2"]


@pytest.mark.parametrize(
    "old,new",
    [
        ("2 exit_group(0)", "2 exit_group(1)"),
        ("WEXITED|__WCLONE", "WEXITED"),
        ("si_pid=2,", "si_pid=4,"),
        ("si_signo=SIGCHLD,", "si_signo=SIGUSR1,"),
        ("P_PIDFD, 12,", "P_PIDFD, 19,"),
        (
            "1 clone(child_stack=NULL, flags=CLONE_VM|CLONE_PIDFD|CLONE_VFORK <unfinished ...>",
            "9 clone(child_stack=NULL, flags=CLONE_VM|CLONE_PIDFD|CLONE_VFORK <unfinished ...>",
        ),
        ("2 exit_group(0) = ?", '2 openat(AT_FDCWD, "/source/code", O_RDONLY) = 4\n2 exit_group(0) = ?'),
        ("parent_tid=[12]) = 2", "parent_tid=[12]) = -1 EPERM"),
        ("1 <... clone resumed>, parent_tid=[12]) = 2", ""),
    ],
)
def test_unrecognized_or_incomplete_pidfd_probe_is_refused(old, new):
    with pytest.raises(ValueError):
        trace_admission(pidfd_trace().replace(old, new), "/trusted/go", "/trusted/python")


@pytest.mark.parametrize(
    "extra",
    [
        'execve("/source/setup.py", [], []) = -1 EACCES',
        'execveat(1, "project", [], [], 0) = -1 EACCES',
        "socket(AF_INET, SOCK_STREAM, 0) = -1 EPERM",
        "socketpair(AF_UNIX, SOCK_STREAM, 0, []) = -1 EPERM",
        "fork() = -1 EPERM",
        "clone(flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = -1 EPERM",
    ],
)
def test_denied_network_or_unexpected_process_attempt_is_still_refused(extra):
    with pytest.raises(ValueError):
        trace_admission('execve("/trusted/go", [], []) = 0\n' + extra, "/trusted/go")


def bundle():
    occurrence = {"package": "pypi:foo@1", "path": "uv.lock", "root": ".", "locator": "package[0]"}
    expected_id = "m046-7b25b98d16ac867b8182a32982dc20f9df8d10399fadc885b64244f96298acb5"
    return {
        "sidecar": {
            "inventory": {"semantic_dimensions": {"occurrences": [occurrence], "relationships": []}},
            "projection": {
                "occurrences": [{"index": 0, "syft_id": expected_id}],
                "relationships": [],
                "unmapped_relationships": [],
            },
        },
        "syft": {
            "artifacts": [
                {
                    "id": expected_id,
                    "name": "foo",
                    "version": "1",
                    "type": "python",
                    "purl": "pkg:pypi/foo@1",
                    "foundBy": "m046-static-python-cataloger",
                    "locations": [
                        {
                            "path": "uv.lock",
                            "annotations": {"m046:locator": "package[0]", "m046:occurrence": expected_id},
                        }
                    ],
                }
            ],
            "artifactRelationships": [],
        },
    }


def test_projection_retains_bijective_selected_occurrence():
    assert verify_projection(bundle()) == {"occurrences": 1, "relationships": 0, "unmapped_relationships": 0}


@pytest.mark.parametrize(
    "field,value",
    [("id", "changed"), ("name", "wrong"), ("version", ">=1"), ("type", "npm"), ("purl", "pkg:pypi/wrong@1")],
)
def test_changed_selected_artifact_is_rejected(field, value):
    document = bundle()
    document["syft"]["artifacts"][0][field] = value
    with pytest.raises(ValueError):
        verify_projection(document)


def test_forged_or_lost_location_and_locator_are_rejected():
    document = bundle()
    document["syft"]["artifacts"][0]["locations"][0]["annotations"]["m046:locator"] = "different"
    with pytest.raises(ValueError):
        verify_projection(document)


def test_consistently_forged_ids_do_not_prove_canonical_identity():
    document = bundle()
    document["sidecar"]["projection"]["occurrences"][0]["syft_id"] = "forged"
    document["syft"]["artifacts"][0]["id"] = "forged"
    document["syft"]["artifacts"][0]["locations"][0]["annotations"]["m046:occurrence"] = "forged"
    with pytest.raises(ValueError, match="id-or-purl"):
        verify_projection(document)


def test_duplicate_custom_artifact_cannot_hide_in_id_index():
    document = bundle()
    document["syft"]["artifacts"].append(deepcopy(document["syft"]["artifacts"][0]))
    with pytest.raises(ValueError, match="duplicate-occurrence-id"):
        verify_projection(document)


@pytest.mark.parametrize(
    "field,value",
    [("parent", "pypi:wrong@1"), ("root", "nested"), ("path", "other.lock"), ("parent_locator", "package[1]")],
)
def test_self_consistent_graph_with_wrong_rich_endpoint_is_rejected(field, value):
    document = bundle()
    identifier = document["syft"]["artifacts"][0]["id"]
    edge = {
        "parent": "pypi:foo@1",
        "child": "pypi:foo@1",
        "root": ".",
        "path": "uv.lock",
        "parent_locator": "package[0]",
    }
    projection = document["sidecar"]["projection"]
    projection["relationships"] = [{"index": 0, "parent_syft_id": identifier, "child_syft_id": identifier}]
    document["sidecar"]["inventory"]["semantic_dimensions"]["relationships"] = [edge]
    document["syft"]["artifactRelationships"] = [
        {"parent": identifier, "child": identifier, "type": "m046-informational-dependency", "metadata": edge}
    ]
    assert verify_projection(document)["relationships"] == 1
    edge[field] = value
    with pytest.raises(ValueError, match="relationship-provenance"):
        verify_projection(document)


def test_unique_graph_edge_cannot_be_silently_unmapped():
    document = bundle()
    edge = {"parent": "pypi:foo@1", "child": "pypi:foo@1", "root": ".", "path": "uv.lock"}
    document["sidecar"]["inventory"]["semantic_dimensions"]["relationships"] = [edge]
    document["sidecar"]["projection"]["unmapped_relationships"] = [0]
    document["sidecar"]["projection"]["unmapped_reasons"] = {"0": "ambiguous-child-occurrence"}
    with pytest.raises(ValueError, match="relationship-provenance"):
        verify_projection(document)


def test_cpe_control_comparison_ignores_only_cpes_and_tool_descriptor():
    left = {
        "artifacts": [{"id": "one", "name": "foo", "cpes": []}],
        "artifactRelationships": [],
        "descriptor": {"on": False},
    }
    right = deepcopy(left)
    right["artifacts"][0]["cpes"] = ["generated"]
    right["descriptor"] = {"on": True}
    assert non_cpe(left) == non_cpe(right)
    right["artifacts"][0]["name"] = "wrong"
    assert non_cpe(left) != non_cpe(right)


@pytest.mark.parametrize("changed", ["binary_sha256", "candidate_sources"])
def test_preparation_mismatch_refuses_before_creating_evidence(tmp_path, monkeypatch, changed):
    monkeypatch.setattr(syft_native, "runtime_identity", lambda: {})
    monkeypatch.setattr(syft_native, "native_elf", lambda _path: None)
    monkeypatch.setattr(syft_native, "candidate_source_identity", lambda: {"go_sources": "current"})
    monkeypatch.setattr(syft_native, "identity", lambda _path: {"binary_sha256": "current"})
    manifest = {"binary_sha256": "current", "candidate_sources": {"go_sources": "current"}}
    manifest[changed] = "stale"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    output = tmp_path / "evidence"
    with pytest.raises(ValueError, match="preparation-source-or-binary-mismatch"):
        syft_native.run(output, tmp_path / "strace", tmp_path / "binary", path)
    assert not output.exists()
