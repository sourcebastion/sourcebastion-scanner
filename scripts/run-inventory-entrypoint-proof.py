"""Trusted finite CI driver; not a production Docker admission supervisor."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import shutil
import sys
import time

MAX_CAPTURE = 65536


def render(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def write(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)


def capture(command, stdout, stderr, *, seconds):
    """Retain bounded complete streams or fail, with a finite client watchdog."""
    deadline = time.monotonic() + seconds
    with stdout.open("xb") as out, stderr.open("xb") as err:
        with selectors.DefaultSelector() as selector:
            process = subprocess.Popen(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True,
            )
            primary = None
            try:
                selector.register(process.stdout, selectors.EVENT_READ, [out, 0])
                selector.register(process.stderr, selectors.EVENT_READ, [err, 0])
                while selector.get_map():
                    if time.monotonic() >= deadline:
                        raise TimeoutError("finite-ci-client-watchdog")
                    for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                        raw = os.read(key.fileobj.fileno(), 8192)
                        if not raw:
                            selector.unregister(key.fileobj)
                            continue
                        stream, count = key.data
                        stream.write(raw[: max(0, MAX_CAPTURE - count)])
                        key.data[1] += len(raw)
                        if key.data[1] > MAX_CAPTURE:
                            raise ValueError("finite-ci-capture-overflow")
                return process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except BaseException as error:
                primary = error
                raise
            finally:
                # This drains/reaps the fresh Docker CLI leader only. The
                # driver separately removes the exact container it created.
                # Neither operation attests production all-descendant custody.
                try:
                    if process.poll() is None or selector.get_map():
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    process.stdout.close()
                    process.stderr.close()
                    process.wait(timeout=5)
                except BaseException as cleanup:
                    if primary is None:
                        raise
                    primary.add_note("finite-ci-client-cleanup-failed:" + type(cleanup).__name__)


def proc_value(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(4097)
    if not 0 < len(raw) <= 4096:
        raise ValueError("finite-ci-clock-observation-unavailable")
    return raw.decode()


def bounded_json(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_CAPTURE + 1)
    if not raw or len(raw) > MAX_CAPTURE:
        raise ValueError("finite-ci-document-bound")
    return json.loads(raw)


def owned_container(run, proof, label, options, image, command, *, seconds, absolute_deadline=None):
    """Create/start/remove one fresh exact CID; uncertain ownership is failure."""
    deadline = time.monotonic() + seconds if absolute_deadline is None else absolute_deadline
    cidfile = proof / (label + ".cid")
    if cidfile.exists() or cidfile.is_symlink():
        raise ValueError("finite-ci-cidfile-already-exists")
    cid, primary, facts = None, None, dict(label=label, image_id=image)

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError("finite-ci-container-watchdog")
        return value

    try:
        create_error = None
        try:
            code = run([
                "docker", "create", "--cidfile", str(cidfile), *options, image, *command,
            ], label + "-create", seconds=min(30, remaining()))
        except BaseException as error:
            create_error = error
        try:
            # Docker may have written its private CID before a CLI timeout.
            # This path is admitted empty immediately before this create call.
            if cidfile.is_file():
                fd = os.open(cidfile, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                        raise ValueError("finite-ci-cidfile-unsafe")
                    raw = os.read(fd, 66)
                finally:
                    os.close(fd)
                candidate = raw.decode("ascii").strip()
                if re.fullmatch(r"[0-9a-f]{64}", candidate) and len(raw) <= 65:
                    cid = candidate
                    facts["container_id"] = cid
        except BaseException as admission:
            facts["cid_admission_failure"] = type(admission).__name__
            if create_error is None:
                create_error = admission
        if create_error is not None:
            raise create_error
        if code != 0 or cid is None:
            raise ValueError("finite-ci-owned-container-create-failed")
        if (proof / (label + "-create.stdout")).read_text().strip() != cid:
            raise ValueError("finite-ci-owned-container-id-mismatch")
        if run(["docker", "inspect", cid], label + "-inspect-before", seconds=min(30, remaining())) != 0:
            raise ValueError("finite-ci-owned-container-inspect-failed")
        actual = bounded_json(proof / (label + "-inspect-before.stdout"))
        if len(actual) != 1 or actual[0]["Id"] != cid or actual[0]["Image"] != image:
            raise ValueError("finite-ci-owned-container-image-mismatch")
        code = run(["docker", "start", "--attach", cid], label, seconds=remaining())
        facts["exit_code"] = code
        if code != 0:
            raise ValueError("finite-ci-owned-container-nonzero")
        if run(["docker", "inspect", cid], label + "-inspect-after", seconds=min(30, remaining())) != 0:
            raise ValueError("finite-ci-owned-container-final-inspect-failed")
        actual = bounded_json(proof / (label + "-inspect-after.stdout"))
        if (
            len(actual) != 1 or actual[0]["Id"] != cid or actual[0]["Image"] != image
            or actual[0]["State"]["Running"] or actual[0]["State"]["ExitCode"] != 0
        ):
            raise ValueError("finite-ci-owned-container-state-mismatch")
    except BaseException as error:
        primary = error
        facts["first_failure"] = type(error).__name__
    finally:
        if cid is not None:
            try:
                code = run(["docker", "rm", "--force", cid], label + "-remove", seconds=20)
                facts["remove_exit_code"] = code
                if code != 0:
                    raise ValueError("finite-ci-owned-container-remove-failed")
            except BaseException as cleanup:
                facts["cleanup_failure"] = type(cleanup).__name__
                if primary is None:
                    primary = cleanup
        else:
            facts["ownership"] = "no-admitted-cid; creation uncertainty is not acceptance"
        try:
            write(proof / (label + "-owned-container.json"), render(facts))
        except BaseException as retention:
            if primary is None:
                primary = retention
            else:
                primary.add_note("finite-ci-ownership-retention-failed:" + type(retention).__name__)
    if primary is not None:
        raise primary
    return facts


def _run(args, proof):
    observations = dict(
        status="finite-ci-proof-incomplete", scope="Finite native entrypoint proof only; no host/kernel/wholeS04 acceptance",
        boot_id=proc_value("/proc/sys/kernel/random/boot_id").strip(),
        timens_offsets=proc_value("/proc/self/timens_offsets"),
    )
    def run(command, label, *, seconds=30):
        out, err = proof / (label + ".stdout"), proof / (label + ".stderr")
        code = capture(command, out, err, seconds=seconds)
        observations.setdefault("commands", []).append(dict(label=label, exit_code=code))
        return code

    primary = None
    try:
        if run(["docker", "image", "inspect", args.image], "image-inspect") != 0:
            raise ValueError("finite-ci-image-inspect-failed")
        inspected = bounded_json(proof / "image-inspect.stdout")
        if type(inspected) is not list or len(inspected) != 1:
            raise ValueError("finite-ci-image-inspect-invalid")
        image = inspected[0]["Id"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
            raise ValueError("finite-ci-image-identity-invalid")
        observations["image_id"] = image
        uid, gid = os.getuid(), os.getgid()
        if uid == 0:
            raise ValueError("finite-ci-nonroot-host-required")
        options = [
            "--init", "--no-healthcheck", "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--user", f"{uid}:{gid}",
            "--cpus", "2", "--memory", "2g", "--memory-swap", "2g", "--pids-limit", "256",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m", "--entrypoint", "python",
            "-e", "PYTHONPATH=", "-e", "HOME=/tmp", "-e", "PYTHONDONTWRITEBYTECODE=1",
            "-v", str(args.checkout) + ":/src:ro", "-w", "/",
            "-v", str(args.source) + ":/source:ro",
            "-v", str(args.advisories) + ":/advisories:ro",
            "-v", str(args.preparation) + ":/preparation:ro",
        ]
        preparation_options = ["-v", str(proof) + ":/proof"]
        verifier = ["-I", "/src/scripts/verify-inventory-entrypoint.py"]
        observations["preparation_started"] = time.monotonic()
        observations["preparation_container"] = owned_container(
            run, proof, "image-prepare", options + preparation_options,
            image, verifier + ["prepare"], seconds=180,
        )
        observations["preparation_finished"] = time.monotonic()
        recipe = bounded_json(proof / "control-recipe.json")
        before = bounded_json(proof / "image-preparation.json")
        if (
            before["boot_id"] != observations["boot_id"]
            or before["timens_offsets"] != observations["timens_offsets"]
            or not observations["preparation_started"] <= before["monotonic"] <= observations["preparation_finished"]
        ):
            raise ValueError("finite-ci-clock-observation-mismatch")
        control, output = proof / "control", proof / "artifacts"
        control.mkdir(mode=0o700)
        output.mkdir(mode=0o700)
        observations["admission_started"] = time.monotonic()
        observations["absolute_deadline"] = observations["admission_started"] + 150
        recipe["deadline_monotonic"] = observations["absolute_deadline"]
        raw = render(recipe)
        if len(raw) > MAX_CAPTURE:
            raise ValueError("finite-ci-control-bound")
        record = control / "job.json"
        write(record, raw)
        record.chmod(0o444)
        control.chmod(0o555)
        observations["control_sha256"] = hashlib.sha256(raw).hexdigest()
        child_options = ["-v", str(control) + ":/control:ro", "-v", str(output) + ":/out"]
        remaining = observations["absolute_deadline"] - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("finite-ci-admission-deadline")
        # The full composition/export/real-matching job now runs under the
        # same finite host cgroup observer as the release stress arms. The
        # controller's original absolute deadline is preserved in job.json.
        resource_output = proof / "entrypoint-resources"
        code = run([
            sys.executable, str(Path(__file__).with_name("run-inventory-resource-proof.py")),
            "--image", image, "--checkout", str(args.checkout), "--workload", "entrypoint",
            "--source", str(args.source), "--advisories", str(args.advisories),
            "--preparation", str(args.preparation), "--control", str(control),
            "--artifacts", str(output), "--output", str(resource_output),
        ], "entrypoint-resource-driver", seconds=remaining + 25)
        resources = bounded_json(resource_output / "resources.json")
        observations["resources"] = resources
        if code != 0 or resources["status"] != "passed":
            raise ValueError("finite-ci-entrypoint-resource-gate-failed")
        shutil.copyfile(resource_output / "workload.json", proof / "entrypoint.stdout")
        actual = {"container_id": resources["container_id"], "exit_code": resources["exit_code"],
                  "remove_exit_code": 0 if resources["removed"] else 1}
        observations["container_id"] = actual["container_id"]
        observations["entry_exit_code"] = actual["exit_code"]
        observations["container_remove_exit_code"] = actual["remove_exit_code"]
        observations["child_finished"] = time.monotonic()
    except BaseException as error:
        primary = error
        observations["first_failure"] = type(error).__name__
    finally:
        if primary is None:
            observations["status"] = "child-exited-zero-and-owned-container-removed"
        try:
            write(proof / "host-observation.json", render(observations))
        except BaseException as retention:
            if primary is None:
                primary = retention
            else:
                primary.add_note("finite-ci-host-retention-failed:" + type(retention).__name__)
    if primary is not None:
        raise primary
    verify_options = [
        "-v", str(proof) + ":/proof", "-v", str(proof / "control") + ":/control:ro",
        "-v", str(proof / "artifacts") + ":/out:ro",
    ]
    owned_container(
        run, proof, "image-verify", options + verify_options,
        image, verifier + ["verify"], seconds=180,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("image", "checkout", "source", "advisories", "preparation", "output"):
        parser.add_argument("--" + name, required=True, type=str if name == "image" else Path)
    args = parser.parse_args()
    os.umask(0o077)
    for name in ("checkout", "source", "advisories", "preparation", "output"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    proof = args.output
    if not proof.is_dir() or proof.stat().st_uid != os.getuid() or proof.stat().st_mode & 0o777 != 0o700 or any(proof.iterdir()):
        raise ValueError("private-empty-proof-root-required")
    def interrupted(_signum, _frame):
        raise InterruptedError("finite-ci-parent-interrupted")

    previous = signal.signal(signal.SIGTERM, interrupted)
    result = dict(status="finite-ci-driver-incomplete")
    try:
        _run(args, proof)
        result["status"] = "finite-ci-driver-passed"
    except BaseException as error:
        result["first_failure"] = type(error).__name__
        raise
    finally:
        signal.signal(signal.SIGTERM, previous)
        try:
            write(proof / "driver-final.json", render(result))
        except BaseException:
            if "first_failure" not in result:
                raise


if __name__ == "__main__":
    main()
