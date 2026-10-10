"""Trusted image preparation of the static maintained Go source parser only."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
from urllib.request import urlopen


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def prepare(output):
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if architecture is None or platform.system() != "Linux":
        raise ValueError("native-linux-go-preparation-required")
    root = Path(__file__).resolve().parents[1]
    source = root / "cmd/inventory-provider"
    names = ("go.mod", "go.sum", "main.go", "main_test.go", "toolchain.json", "gomod/main.go", "gomod/main_test.go")
    source_files = {name: sha(source / name) for name in names}
    pins = json.loads((source / "toolchain.json").read_text())
    output.mkdir(parents=True, exist_ok=False)
    archive = output / "go.tar.gz"
    url = f"https://go.dev/dl/go{pins['version']}.linux-{architecture}.tar.gz"
    size = 0
    with urlopen(url, timeout=60) as response, archive.open("xb") as stream:
        while chunk := response.read(1024**2):
            size += len(chunk)
            if size > 256 * 1024**2:
                raise ValueError("go-archive-preparation-bound")
            stream.write(chunk)
    if sha(archive) != pins[f"linux_{architecture}_sha256"]:
        raise ValueError("go-archive-digest-mismatch")
    with tarfile.open(archive) as package:
        package.extractall(output, filter="data")
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC", "GOTOOLCHAIN": "local", "GOWORK": "off",
           "GOENV": "off", "GOFLAGS": "-mod=readonly", "GOCACHE": str(output / "cache"), "GOPATH": str(output / "modules"),
           "GOMAXPROCS": "2", "GOOS": "linux", "GOARCH": architecture, "CGO_ENABLED": "0", "GOAMD64": "v1", "GOARM64": "v8.0",
           "GOPROXY": "https://proxy.golang.org", "GOSUMDB": "sum.golang.org"}
    go = output / "go/bin/go"
    def run(label, arguments):
        with (output / (label + ".stdout")).open("xb") as out, (output / (label + ".stderr")).open("xb") as err:
            subprocess.run([str(go), *arguments], cwd=source, env=env, stdout=out, stderr=err, check=True, timeout=900)
        if {name: sha(source / name) for name in names} != source_files:
            raise ValueError("changed-go-preparation-source")
    # Hydrate reviewed module metadata in maintenance, then forbid downloads
    # during tests/build. No customer source is admitted to this stage.
    run("hydrate", ["list", "-m", "-json", "all"])
    run("download", ["mod", "download", "golang.org/x/mod"])
    env.update(GOPROXY="off", GOSUMDB="off")
    run("test", ["test", "-trimpath", "-count=1", "-p", "2", "-timeout", "90s", "./gomod"])
    binary = output / "sourcebastion-go-source"
    run("build", ["build", "-trimpath", "-buildvcs=false", "-p", "2", "-o", str(binary), "./gomod"])
    run("buildinfo", ["version", "-m", str(binary)])
    run("module", ["list", "-m", "-json", "golang.org/x/mod"])
    module = json.loads((output / "module.stdout").read_text())
    notices = output / "notices"
    notices.mkdir()
    for name, path in (("Go-LICENSE", output / "go/LICENSE"), ("x-mod-LICENSE", Path(module["Dir"]) / "LICENSE"),
                       ("SourceBastion-LICENSE", root / "LICENSE")):
        shutil.copyfile(path, notices / name)
    (output / "manifest.json").write_text(json.dumps({
        "schema_version": "sourcebastion.go-image-preparation/1", "architecture": architecture,
        "go_version": pins["version"], "go_archive_sha256": sha(archive), "source_files": source_files,
        "binary_sha256": sha(binary), "binary_bytes": binary.stat().st_size, "cgo_enabled": "0",
        "module": {key: module[key] for key in ("Path", "Version", "Sum", "GoModSum")},
        "notices": {path.name: sha(path) for path in notices.iterdir()},
        "buildinfo_sha256": sha(output / "buildinfo.stdout"),
    }, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    prepare(parser.parse_args().output.resolve())
