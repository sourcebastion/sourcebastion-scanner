"""Finite native proof of an already published digest; never whole-S07 acceptance."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

from m046_published import IMAGE, S01_ARTIFACTS, bind_native, extract_s01, native_descriptor, verify_advisories
from inventory_release import frozen_s01_layers, growth, oci_layers
from inventory_execution_observation import verify_observation

DRIVER = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--index", required=True, type=Path)
    parser.add_argument("--checkout", required=True, type=Path)
    parser.add_argument("--advisories", required=True, type=Path)
    parser.add_argument("--advisory-manifest", required=True, type=Path)
    parser.add_argument("--advisory-manifest-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--temporary", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    args.temporary.mkdir(mode=0o700)
    receipt = {"schema_version": "m046.published-native-proof/1", "status": "failed", "acceptance": False,
               "remaining_acceptance": ["complete execution/network observation", "adversarial timeout/cancellation/controller-loss",
                                        "development human acceptance", "mixed-version rollback", "all-slice acceptance"]}

    def run(command, label, *, seconds=600, environment=None):
        # Commands and captures are maintainer-selected, never customer input.
        with (args.output / (label + ".stdout")).open("xb") as out, (args.output / (label + ".stderr")).open("xb") as err:
            subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                           timeout=seconds, check=True, cwd=args.checkout, env=environment)

    try:
        architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
        if platform.system() != "Linux" or architecture is None or os.getuid() == 0:
            raise ValueError("nonroot-native-linux-runner-required")
        identity = json.loads(args.identity.read_bytes())
        source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=args.checkout, timeout=15).decode().strip()
        if source != identity["source_sha"] or subprocess.check_output(
                ["git", "status", "--porcelain", "--untracked-files=no"], cwd=args.checkout, timeout=15):
            raise ValueError("release-checkout-identity-mismatch")
        index_digest = identity["image"].removeprefix(IMAGE + "@")
        descriptor = native_descriptor(args.index.read_bytes(), index_digest, architecture)
        native = IMAGE + "@" + descriptor["digest"]
        receipt.update(identity)
        receipt["shared_advisory_manifest_sha256"] = args.advisory_manifest_sha256
        receipt["advisory_snapshot_file_sha256"] = verify_advisories(
            args.advisories, args.advisory_manifest, args.advisory_manifest_sha256)
        run(["skopeo", "inspect", "--raw", "docker://" + native], "native-manifest")
        run(["docker", "pull", "--platform", "linux/" + architecture, native], "pull")
        run(["docker", "image", "inspect", "--format", "{{json .}}", native], "image-inspect")
        inspected = json.loads((args.output / "image-inspect.stdout").read_bytes())
        receipt.update(bind_native((args.output / "native-manifest.stdout").read_bytes(), descriptor, inspected, architecture))
        image = inspected["Id"]
        candidate_archive = args.temporary / "candidate.oci.tar"
        run(["skopeo", "copy", "--preserve-digests", "docker://" + native,
             "oci-archive:" + str(candidate_archive)], "retain-compressed-layers", seconds=900)
        baseline_zip, baseline_archive = args.temporary / "s01.zip", args.temporary / "s01.oci.tar"
        with baseline_zip.open("xb") as stream:
            subprocess.run(["gh", "api", f"repos/sourcebastion/sourcebastion-scanner/actions/artifacts/{S01_ARTIFACTS[architecture]}/zip"],
                           stdin=subprocess.DEVNULL, stdout=stream, timeout=600, check=True)
        extract_s01(baseline_zip, baseline_archive, architecture)
        baseline = frozen_s01_layers(baseline_archive, architecture)
        candidate = oci_layers(candidate_archive, architecture)
        if candidate["manifest_digest"] != descriptor["digest"] or candidate["config_digest"] != image:
            raise ValueError("retained-oci-is-not-published-native-image")
        size = {"status": "passed", **growth(baseline, candidate), "tested_image_id": image,
                **{key: val for key, val in baseline.items() if key.startswith("baseline_")}}
        (args.output / "frozen-s01-growth.json").write_text(json.dumps(size, sort_keys=True))
        for workload, label in (("packaging", "installed-packaging"), ("cyclonedx", "cyclonedx-generated")):
            output = args.output / (label + "-resources")
            run([sys.executable, str(DRIVER / "run-inventory-resource-proof.py"), "--image", image,
                 "--checkout", str(args.checkout), "--workload", workload, "--output", str(output)], label, seconds=200)
            (args.output / (label + "-workload.json")).write_bytes((output / "workload.json").read_bytes())
        run([sys.executable, str(args.checkout / "scripts/validate-inventory-cyclonedx.py"),
             str(args.output / "cyclonedx-generated-workload.json")], "cyclonedx-validation", seconds=150)
        run([sys.executable, str(DRIVER / "run-inventory-resource-proof.py"), "--image", image,
             "--checkout", str(args.checkout), "--workload", "corpus", "--observe-execution",
             "--output", str(args.output / "observed-corpus-resources")], "observed-corpus", seconds=200)
        run([sys.executable, str(DRIVER / "run-inventory-resource-matrix.py"), "--image", image,
             "--checkout", str(args.checkout), "--output-root", str(args.output), "--repeats", "3", "--concurrency", "3"],
            "resource-matrix", seconds=3600)
        (args.output / "source-expectations.stdout").write_bytes((args.output / "inventory-resources-corpus-1/workload.json").read_bytes())
        run([sys.executable, str(args.checkout / "scripts/verify-inventory-upgrade.py"),
             "--baseline", str(args.checkout / "evaluation/m046/canonical-source-expectations-v1.json"),
             "--candidate", str(args.output / "source-expectations.stdout"),
             "--output", str(args.output / "current-oracle-diff.json")], "oracle-gate")
        environment = {**os.environ, "SOURCEBASTION_NATIVE_PROOF_CHECKOUT": str(args.checkout),
                       "SOURCEBASTION_NATIVE_OBSERVE_EXECUTION": "1",
                       "SOURCEBASTION_NATIVE_ADVISORIES": str(args.advisories),
                       "SOURCEBASTION_NATIVE_GRYPE_PROOF_OUTPUT": str(args.output / "real-grype"),
                       "SOURCEBASTION_NATIVE_DEPENDENCY_JOB_OUTPUT": str(args.output / "dependency-job"),
                       "SOURCEBASTION_NATIVE_ENTRYPOINT_OUTPUT": str(args.output / "entrypoint")}
        environment.pop("SOURCEBASTION_UPGRADE_BASE_IMAGE", None)
        environment.pop("SOURCEBASTION_UPGRADE_BASE_CHECKOUT", None)
        run(["bash", str(DRIVER / "smoke-scan-hosted.sh"), image], "hosted-frozen-advisories", seconds=1200, environment=environment)
        observation_roots = [args.output / "observed-corpus-resources"] + [
            args.output / f"entrypoint/repeat-{repeat}/entrypoint-resources" for repeat in range(1, 4)]
        receipt["execution_observation_traces"] = {
            path.relative_to(args.output).as_posix(): verify_observation(path) for path in observation_roots}
        consumer = json.loads((args.output / "real-grype/receipt.json").read_bytes())["consumer"]
        if consumer["advisory_snapshot_sha256"] != args.advisory_manifest_sha256:
            raise ValueError("consumer-did-not-use-shared-advisory-generation")
        receipt["advisory_snapshot_sha256"] = consumer["advisory_snapshot_sha256"]
        # Recheck the shared generation and source after every proof stage.
        verify_advisories(args.advisories, args.advisory_manifest, args.advisory_manifest_sha256)
        if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=args.checkout, timeout=15):
            raise ValueError("release-source-mutated")
        receipt["status"] = "finite-published-native-passed"
    except Exception as error:
        receipt["reason"] = type(error).__name__
        receipt["detail"] = str(error)[:2048]
    finally:
        receipt["retained_files"] = {
            path.relative_to(args.output).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(args.output.rglob("*")) if path.is_file()}
        (args.output / "receipt.json").write_text(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["status"] == "finite-published-native-passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
