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
    # APK signature checking remains enabled at installation, in addition to
    # the preparation SHA256 check. Check actual package versions offline.
    for name, row in pins["packages"].items():
        observed = subprocess.run(["/sbin/apk", "info", "-v", name], check=True, capture_output=True, timeout=5).stdout.decode().strip()
        if observed != name + "-" + row["version"]:
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
    identities = ["PYTHON_VERSION", "images/Dockerfile", ".github/inventory-runtime-pins.json", ".github/scanner-versions.json",
                  ".github/semgrep-artifacts.json", "cmd/inventory-provider/go.mod", "cmd/inventory-provider/go.sum",
                  "cmd/inventory-provider/toolchain.json", "evaluation/m046/cyclonedx-schemas/pins.json",
                  "evaluation/m046/release-budgets-v1.json"]
    identities.extend(".github/python-locks/" + path.name for path in sorted((root / ".github/python-locks").iterdir()) if path.is_file())
    print(json.dumps({
        "schema_version": "m046.installed-inventory-packaging/1", "status": "passed", "architecture": architecture,
        "python": platform.python_version(), "node": node_version, "registry_version": registry.VERSION,
        "registry_sha256": registry.REGISTRY_SHA256, "installed_modules": source_files,
        "go": go,
        "pin_files": {name: sha((root / name).read_bytes()) for name in identities},
        "runtime_distributions": {dist.metadata["Name"]: dist.version for dist in metadata.distributions()},
        "scope": "Installed module/pin/version closure only; separate verified wheel/APK preparation, OCI/resources, native real matching and distribution-license review remain required.",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
