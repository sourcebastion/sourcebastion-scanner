"""Exercise installed pinned runtime and preserve maintenance closure identities."""

import hashlib
from importlib import metadata
import json
from pathlib import Path
import platform
import subprocess
import sys


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def installed_apks(raw):
    if not raw or len(raw) > 16 * 1024**2:
        raise ValueError("installed-apk-metadata-bound")
    packages = {}
    for block in raw.decode("utf-8").split("\n\n"):
        if not block.strip():
            continue
        names = [line[2:] for line in block.splitlines() if line.startswith("P:")]
        versions = [line[2:] for line in block.splitlines() if line.startswith("V:")]
        if len(names) != 1 or len(versions) != 1 or not names[0] or not versions[0] or names[0] in packages:
            raise ValueError("installed-apk-metadata-invalid")
        packages[names[0]] = versions[0]
    if not packages:
        raise ValueError("installed-apk-metadata-empty")
    return packages


def native_distribution_closure(distributions, expected, retained, original, source_reference=None):
    """Compare installed wheel files and retained notices to reviewed inputs."""
    def notice_files(root):
        result = {}
        if root.is_symlink():
            raise ValueError("installed-native-notice-symlink")
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                raise ValueError("installed-native-notice-symlink")
            if path.is_file():
                result[path.relative_to(root).as_posix()] = sha(path.read_bytes())
        return result
    notice_hashes = notice_files(original)
    if not notice_hashes or notice_files(retained) != notice_hashes:
        raise ValueError("installed-native-notice-mismatch")
    if source_reference is not None and source_reference not in (retained / "SOURCE-AVAILABILITY.md").read_text():
        raise ValueError("installed-native-source-directions-pending-or-mismatched")
    observed = []
    for dist in distributions:
        name = dist.metadata["Name"].lower().replace("_", "-").replace(".", "-")
        for member in dist.files or ():
            path = Path(member)
            vendored = any(part.endswith(".libs") for part in path.parts[:-1])
            vendored |= "/semgrep/bin/libs/" in "/" + path.as_posix()
            vendored |= path.name.startswith("lib") and ".so" in path.name
            if not vendored or ".so" not in path.name:
                continue
            installed = Path(dist.locate_file(member))
            if installed.is_symlink():
                raise ValueError("installed-native-library-symlink")
            raw = installed.read_bytes()
            if not raw.startswith(b"\x7fELF"):
                raise ValueError("installed-native-library-not-elf")
            observed.append({"distribution": name, "version": dist.version,
                             "path": path.as_posix(), "sha256": sha(raw), "bytes": len(raw)})
    selected = [{key: row[key] for key in ("distribution", "version", "path", "sha256", "bytes")}
                for row in expected]
    for row in selected:
        row["path"] = row["path"].split(".data/purelib/", 1)[-1]
    order = lambda row: (row["distribution"], row["path"])
    if sorted(observed, key=order) != sorted(selected, key=order):
        raise ValueError("installed-native-library-closure-mismatch")
    return {"libraries": sorted(observed, key=order), "notice_files": notice_hashes}


def main():
    if sys.flags.optimize:
        raise ValueError("optimized-packaging-proof-refused")
    from sourcebastion.inventory import contract, registry
    root = Path.cwd()
    installed = Path(contract.__file__).resolve().parent
    if installed.is_relative_to(root):
        raise ValueError("installed-inventory-required")
    def files(directory):
        return {path.relative_to(directory).as_posix(): sha(path.read_bytes())
                for path in sorted(directory.rglob("*"))
                if path.is_file() and path.suffix in {".py", ".cjs", ".js", ".json", ".mjs"}}
    source_files = files(root / "sourcebastion/inventory")
    if not source_files or files(installed) != source_files:
        raise ValueError("installed-inventory-closure-mismatch")
    pins_raw = (root / ".github/inventory-runtime-pins.json").read_bytes()
    if (Path("/usr/local/share/sourcebastion/inventory-runtime-pins.json").read_bytes() != pins_raw):
        raise ValueError("installed-inventory-runtime-pins-mismatch")
    pins = json.loads(pins_raw)
    if platform.python_version() != pins["python"] or (root / "PYTHON_VERSION").read_text().strip() != pins["python"]:
        raise ValueError("inventory-python-pin-mismatch")
    machine = platform.machine()
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(machine)
    if platform.system() != "Linux" or architecture is None:
        raise ValueError("native-packaging-proof-required")
    node_version = subprocess.run(["/usr/bin/node", "--version"], check=True, capture_output=True, timeout=5).stdout.decode().strip()
    if node_version != pins["node_version"]:
        raise ValueError("inventory-node-pin-mismatch")
    # APK3's info applet opens repository indexes even for installed package
    # queries, and -v reports descriptions rather than the old version format.
    # Read the installed database directly; no repository command is needed.
    with Path("/lib/apk/db/installed").open("rb") as stream:
        installed_raw = stream.read(16 * 1024**2 + 1)
    apk_versions = installed_apks(installed_raw)
    for name, row in pins["packages"].items():
        if apk_versions.get(name) != row["version"]:
            raise ValueError("inventory-apk-version-mismatch")
    for filename, digest in json.loads((root / ".github/python-locks/manifest.json").read_text())["files"].items():
        if sha((root / ".github/python-locks" / filename).read_bytes()) != digest:
            raise ValueError("inventory-python-lock-hash-mismatch")
    for name in ("npm-semver", "yarn-syml"):
        manifest = json.loads((installed / "vendor" / (name + "-manifest.json")).read_text())
        for filename, digest in manifest["files"].items():
            if sha((installed / "vendor" / name / filename).read_bytes()) != digest:
                raise ValueError("inventory-vendored-parser-hash-mismatch")
    go = json.loads(Path("/usr/local/share/sourcebastion/inventory-go.json").read_text())
    go_pins = json.loads((root / "cmd/inventory-provider/toolchain.json").read_text())
    if (go["architecture"] != architecture or go["cgo_enabled"] != "0" or go["go_version"] != go_pins["version"]
            or go["go_archive_sha256"] != go_pins[f"linux_{architecture}_sha256"]):
        raise ValueError("installed-go-preparation-pin-mismatch")
    for name, digest in go["source_files"].items():
        if sha((root / "cmd/inventory-provider" / name).read_bytes()) != digest:
            raise ValueError("installed-go-source-identity-mismatch")
    binary = Path("/usr/local/bin/sourcebastion-go-source")
    if binary.stat().st_size != go["binary_bytes"] or sha(binary.read_bytes()) != go["binary_sha256"]:
        raise ValueError("installed-go-binary-digest-mismatch")
    for name, digest in go["notices"].items():
        if sha((Path("/usr/local/share/sourcebastion/inventory-go-notices") / name).read_bytes()) != digest:
            raise ValueError("installed-go-license-notice-mismatch")
    native_manifest = json.loads((root / ".github/bundled-native-libraries.json").read_text())
    native_target = "musllinux_1_2_" + machine
    source_pins = json.loads((root / ".github/native-source-pins.json").read_text())
    source_reference = source_pins["repository"] + "@" + source_pins["manifest_digest"]
    native_closure = native_distribution_closure(
        metadata.distributions(), native_manifest["targets"][native_target],
        Path("/usr/local/share/sourcebastion/third-party-notices"), root / "third-party-notices", source_reference)
    identities = [".github/bundled-native-libraries.json", ".github/native-source-pins.json", "PYTHON_VERSION", "images/Dockerfile", ".github/inventory-runtime-pins.json", ".github/scanner-versions.json",
                  ".github/semgrep-artifacts.json", "cmd/inventory-provider/go.mod", "cmd/inventory-provider/go.sum",
                  "cmd/inventory-provider/toolchain.json", "evaluation/m046/cyclonedx-schemas/pins.json",
                  "evaluation/m046/release-budgets-v1.json"]
    identities.extend(".github/python-locks/" + path.name for path in sorted((root / ".github/python-locks").iterdir()) if path.is_file())
    print(json.dumps({
        "schema_version": "m046.installed-inventory-packaging/1", "status": "passed", "architecture": architecture,
        "python": platform.python_version(), "node": node_version, "registry_version": registry.VERSION,
        "registry_sha256": registry.REGISTRY_SHA256, "installed_modules": source_files,
        "go": go, "bundled_native_closure": native_closure, "native_source_reference": source_reference,
        "installed_apk_database_sha256": sha(installed_raw), "installed_apk_versions": apk_versions,
        "pin_files": {name: sha((root / name).read_bytes()) for name in identities},
        "runtime_distributions": {dist.metadata["Name"]: dist.version for dist in metadata.distributions()},
        "scope": "Installed module/pin/version closure only; separate verified wheel/APK preparation, OCI/resources, native real matching and distribution-license review remain required.",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
