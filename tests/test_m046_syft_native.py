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


def terminal_thread_trace():
    return "\n".join(
        [
            '1 execve("/trusted/go", [], []) = 0',
            "1 clone(flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND) = 2",
            "2 clone3({flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND}, 88) = 3",
            "3 exit_group(0 <unfinished ...>",
            "3 +++ exited with 0 +++",
        ]
    )


def test_only_explicit_successful_go_thread_terminal_exit_is_discharged():
    result = trace_admission(terminal_thread_trace(), "/trusted/go")
    assert result["terminal_exit_groups"] == ["3"]
    with pytest.raises(ValueError, match="incomplete-process-trace"):
        syft_native.trace_calls(terminal_thread_trace())


@pytest.mark.parametrize(
    "old,new",
    [
        ("3 +++ exited with 0 +++", ""),
        ("3 +++ exited with 0 +++", "3 +++ exited with 1 +++"),
        ("3 +++ exited with 0 +++", "3 +++ killed by SIGKILL +++"),
        ("3 +++ exited with 0 +++", "+++ exited with 0 +++"),
        ("3 +++ exited with 0 +++", "4 +++ exited with 0 +++"),
        ("3 +++ exited with 0 +++", "3 +++ exited with 0 +++\n3 +++ exited with 0 +++"),
        ("3 +++ exited with 0 +++", '3 +++ exited with 0 +++\n3 openat(AT_FDCWD, "/source", O_RDONLY) = 4'),
        ("3 +++ exited with 0 +++", "3 +++ exited with 0 +++\n2 clone(flags=CLONE_THREAD) = 3"),
        ("3 exit_group(0", "3 exit_group(1"),
        ("3 exit_group(0", '3 openat(AT_FDCWD, "/source", O_RDONLY'),
        ("3 exit_group(0", "3 socket(AF_INET, SOCK_STREAM, 0"),
        ("3 exit_group(0", "3 clone(flags=CLONE_THREAD"),
        ("3 exit_group(0", "9 exit_group(0"),
        ("3 exit_group(0", "1 exit_group(0"),
        ('execve("/trusted/go", [], []) = 0', 'execve("/trusted/go", [], []) = -1 EACCES'),
        ("CLONE_VM|CLONE_THREAD|CLONE_SIGHAND}, 88) = 3", "CLONE_VM|CLONE_THREAD|CLONE_SIGHAND}, 88) = -1 EPERM"),
        ("CLONE_VM|CLONE_THREAD|CLONE_SIGHAND}, 88) = 3", "CLONE_VM|CLONE_VFORK|SIGCHLD}, 88) = 3"),
        ("CLONE_VM|CLONE_THREAD|CLONE_SIGHAND}, 88) = 3", "CLONE_THREAD}, 88) = 3"),
    ],
)
def test_terminal_marker_cannot_excuse_uncertain_or_unrelated_calls(old, new):
    with pytest.raises(ValueError):
        trace_admission(terminal_thread_trace().replace(old, new), "/trusted/go")


@pytest.mark.parametrize(
    "line", ["7 ???( <unfinished ...>", "7 syscall_0xffff(0) = -1 ENOSYS", "strace: detached", "7 openat("]
)
def test_unknown_or_truncated_trace_line_is_never_silently_ignored(line):
    with pytest.raises(ValueError, match="undecoded-process-trace"):
        trace_admission(terminal_thread_trace() + "\n" + line, "/trusted/go")


def test_completed_calls_and_explicit_signal_and_exit_markers_remain_admissible():
    trace = terminal_thread_trace().replace("3 exit_group(0 <unfinished ...>", "3 exit_group(0) = ?")
    trace += "\n1 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED} ---\n1 +++ exited with 0 +++"
    assert trace_admission(trace, "/trusted/go")["terminal_exit_groups"] == []


def test_thread_ancestry_must_be_known_before_unfinished_exit():
    trace = terminal_thread_trace().replace(
        "2 clone3({flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND}, 88) = 3\n3 exit_group(0 <unfinished ...>",
        "3 exit_group(0 <unfinished ...>\n2 clone3({flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND}, 88) = 3",
    )
    with pytest.raises(ValueError, match="reused-process-trace"):
        trace_admission(trace, "/trusted/go")


def test_unknown_terminal_pid_and_pid_zero_are_refused():
    for extra in ("9 +++ exited with 0 +++", "0 exit_group(0) = ?"):
        with pytest.raises(ValueError):
            trace_admission(terminal_thread_trace() + "\n" + extra, "/trusted/go")


def test_original_failed_tail_is_refused_even_if_terminal_evidence_is_added():
    trace = terminal_thread_trace().replace(
        "3 +++ exited with 0 +++", "7 ???( <unfinished ...>\n3 +++ exited with 0 +++"
    )
    with pytest.raises(ValueError, match="undecoded-process-trace"):
        trace_admission(trace, "/trusted/go")


def test_native_admission_requires_terminal_markers_for_all_observed_and_spawned_pids():
    trace = terminal_thread_trace() + "\n2 +++ exited with 0 +++\n1 +++ exited with 0 +++"
    assert trace_admission(trace, "/trusted/go", require_complete=True)["terminal_markers_required"]
    for pid in ("1", "2", "3"):
        with pytest.raises(ValueError):
            trace_admission(trace.replace(f"{pid} +++ exited with 0 +++", ""), "/trusted/go", require_complete=True)
    with pytest.raises(ValueError, match="incomplete-terminal-process-trace"):
        trace_admission('1 execve("/trusted/go", [], []) = 0', "/trusted/go", require_complete=True)


def test_native_admission_requires_terminal_markers_for_unobserved_spawned_child():
    trace = '1 execve("/trusted/go", [], []) = 0\n1 clone(flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND) = 2\n1 +++ exited with 0 +++'
    with pytest.raises(ValueError, match="incomplete-terminal-process-trace"):
        trace_admission(trace, "/trusted/go", require_complete=True)
    assert trace_admission(trace + "\n2 +++ exited with 0 +++", "/trusted/go", require_complete=True)


@pytest.mark.parametrize(
    "extra",
    [
        '9 openat(AT_FDCWD, "/source", O_RDONLY) = 4\n9 +++ exited with 0 +++',
        "9 --- SIGCHLD {si_signo=SIGCHLD} ---",
        "9 --- SIGCHLD {si_signo=SIGCHLD} ---\n9 +++ exited with 0 +++",
        "9 clone(flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND) = 10\n9 +++ exited with 0 +++\n10 +++ exited with 0 +++",
        '9 openat(AT_FDCWD, "/source", O_RDONLY) = 4\n1 clone(flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND) = 9\n9 +++ exited with 0 +++',
    ],
)
def test_orphan_pid_or_spawn_tree_cannot_establish_complete_native_trace(extra):
    trace = '1 execve("/trusted/go", [], []) = 0\n' + extra + "\n1 +++ exited with 0 +++"
    with pytest.raises(ValueError, match="(?:incomplete-terminal|reused)-process-trace"):
        trace_admission(trace, "/trusted/go", require_complete=True)


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


def restarted_waitid_trace():
    return "\n".join(
        [
            '1 execve("/trusted/go", [], []) = 0',
            "1 waitid(P_PIDFD, 12,  <unfinished ...>",
            "1 <... waitid resumed>, 0x123, WEXITED, 0x456) = ? ERESTARTSYS (To be restarted if SA_RESTART is set)",
            "1 --- SIGURG {si_signo=SIGURG, si_code=SI_TKILL} ---",
            "1 waitid(P_PIDFD, 12, {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=2, si_status=0}, WEXITED, NULL) = 0",
            "1 +++ exited with 0 +++",
        ]
    )


@pytest.mark.parametrize("split", [True, False])
def test_decoded_interrupted_waitid_remains_an_attempt_without_success_inference(split):
    trace = restarted_waitid_trace()
    if not split:
        trace = trace.replace("  <unfinished ...>\n1 <... waitid resumed>", " ")
    calls = syft_native.trace_calls(trace, terminal_binary="/trusted/go", require_complete=True)
    assert [name for _pid, name, _args in calls] == ["execve", "waitid", "waitid"]
    assert calls[1][2].endswith("= ? ERESTARTSYS (To be restarted if SA_RESTART is set)")
    assert calls[2][2].endswith("= 0")
    assert trace_admission(trace, "/trusted/go", require_complete=True)["network_attempts"] == 0
    # Signal disposition may instead produce EINTR; no later success required.
    without_reap = trace.replace(trace.splitlines()[-2] + "\n", "")
    assert trace_admission(without_reap, "/trusted/go", require_complete=True)


def test_interrupted_result_does_not_discharge_pending_call_or_missing_terminal():
    trace = restarted_waitid_trace()
    for invalid in (
        trace.replace("1 +++ exited with 0 +++", ""),
        trace.replace("1 +++ exited with 0 +++", "1 waitid(P_PIDFD, 13, <unfinished ...>\n1 +++ exited with 0 +++"),
        trace.replace("1 waitid(P_PIDFD, 12,  <unfinished ...>", ""),
    ):
        with pytest.raises(ValueError):
            trace_admission(invalid, "/trusted/go", require_complete=True)


@pytest.mark.parametrize(
    "result",
    [
        "? ERESTARTSYS",
        "? ERESTARTSYS (unknown)",
        "? ERESTARTSYS (To be restarted if SA_RESTART is set) trailing",
        "? ERESTARTNOHAND (To be restarted if no handler)",
        "? ENOSYS (To be restarted if SA_RESTART is set)",
        "?? ERESTARTSYS (To be restarted if SA_RESTART is set)",
    ],
)
def test_unknown_or_unadmitted_restart_result_remains_refused(result):
    trace = restarted_waitid_trace().replace("? ERESTARTSYS (To be restarted if SA_RESTART is set)", result)
    with pytest.raises(ValueError, match="undecoded-process-trace"):
        trace_admission(trace, "/trusted/go", require_complete=True)


@pytest.mark.parametrize(
    "attempt",
    [
        "socket(AF_INET, SOCK_STREAM, 0)",
        "socketpair(AF_UNIX, SOCK_STREAM, 0, [])",
        "connect(3, {sa_family=AF_INET}, 16)",
        "fork()",
        "clone(flags=CLONE_VM|CLONE_VFORK|SIGCHLD)",
        'execve("/trusted/go", [], [])',
        'execveat(1, "project", [], [], 0)',
    ],
)
def test_restart_pseudo_result_never_hides_network_or_process_attempt(attempt):
    trace = restarted_waitid_trace()
    trace = trace.replace(
        "1 --- SIGURG", f"1 {attempt} = ? ERESTARTSYS (To be restarted if SA_RESTART is set)\n1 --- SIGURG"
    )
    with pytest.raises(ValueError):
        trace_admission(trace, "/trusted/go", require_complete=True)


def test_interrupted_waitid_cannot_establish_successful_pidfd_probe_reap():
    trace = pidfd_trace().replace(
        "WEXITED|__WCLONE, NULL) = 0",
        "WEXITED|__WCLONE, NULL) = ? ERESTARTSYS (To be restarted if SA_RESTART is set)",
    )
    with pytest.raises(ValueError, match="untrusted-pidfd-probe"):
        trace_admission(trace, "/trusted/go", "/trusted/python")


def test_vfork_probe_child_can_exit_before_parent_creation_resumes():
    trace = pidfd_trace().replace("2 exit_group(0) = ?", "2 exit_group(0) = ?\n2 +++ exited with 0 +++")
    assert trace_admission(trace, "/trusted/go", "/trusted/python")["pidfd_probe_children"] == ["2"]


def test_new_creation_after_prior_child_exit_cannot_reuse_pid():
    trace = pidfd_trace().replace("2 exit_group(0) = ?", "2 exit_group(0) = ?\n2 +++ exited with 0 +++")
    trace += "\n1 clone(flags=CLONE_THREAD) = 2"
    with pytest.raises(ValueError, match="reused-process-trace"):
        trace_admission(trace, "/trusted/go", "/trusted/python")


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
