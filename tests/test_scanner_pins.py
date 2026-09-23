"""Static checks for bundled scanner downloads."""

import json
from pathlib import Path


REPO_ROOT = Path(__file__).parents[1]
PINS = json.loads((REPO_ROOT / ".github" / "scanner-versions.json").read_text())


def _scanner_install(text: str, scanner: str) -> str:
    archive = text.index(f"/tmp/{scanner}.tar.gz")
    start = text.rfind("RUN ", 0, archive)
    end = text.index("\n\n", archive)
    return text[start:end]


def test_archived_scanners_use_verified_release_downloads():
    gitleaks = PINS["gitleaks"]
    grype = PINS["grype"]
    expected_archives = {
        "Dockerfile": {
            "gitleaks": [
                gitleaks["linux_arm64_sha256"],
                gitleaks["linux_x64_sha256"],
            ],
            "grype": [
                grype["linux_arm64_sha256"],
                grype["linux_amd64_sha256"],
            ],
        },
        "Dockerfile.micro": {
            "gitleaks": [gitleaks["linux_x64_sha256"]],
            "grype": [grype["linux_amd64_sha256"]],
        },
        "Dockerfile.slim": {
            "gitleaks": [
                gitleaks["linux_arm64_sha256"],
                gitleaks["linux_x64_sha256"],
            ],
            "grype": [
                grype["linux_arm64_sha256"],
                grype["linux_amd64_sha256"],
            ],
        },
        "Dockerfile.thin": {
            "gitleaks": [
                gitleaks["linux_arm64_sha256"],
                gitleaks["linux_x64_sha256"],
            ],
            "grype": [
                grype["linux_arm64_sha256"],
                grype["linux_amd64_sha256"],
            ],
        },
    }

    for dockerfile_name, scanners in expected_archives.items():
        text = (REPO_ROOT / "images" / dockerfile_name).read_text()
        for scanner, digests in scanners.items():
            install = _scanner_install(text, scanner)
            if scanner == "gitleaks":
                version = gitleaks["version"]
                assert f"v{version}/gitleaks_{version}_linux_" in install
            else:
                version = grype["version"]
                assert f"v{version}/grype_{version}_linux_" in install
            assert "sha256sum -c -" in install
            for digest in digests:
                assert digest in install
            assert "install.sh" not in install
