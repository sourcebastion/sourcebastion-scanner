import os
import re
from pathlib import Path

from setuptools import setup, find_packages

HERE = Path(__file__).parent

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()


def _release_version() -> str:
    """The version this build is, read from the one file that declares it.

    `VERSION` is already the authority: `release.yml` refuses to publish
    unless the dispatched tag equals `v$(cat VERSION)`, so the tag and this
    file cannot disagree. Deriving from it means the tag is effectively the
    source of truth and no second copy exists to drift.

    A literal here was that second copy, and it drifted: every release through
    v1.7.34 shipped metadata saying `0.1.0`, so `sourcebastion --version`
    inside a digest-pinned contract scanner could not report which release it
    was.

    `SOURCEBASTION_VERSION` overrides it for a build that is deliberately not
    a release -- a local wheel, a scratch image -- without editing a tracked
    file to do so.

    Missing or malformed input raises. Falling back to a placeholder is what
    produced this bug: the build succeeded and the wrong version shipped.
    """
    override = os.environ.get("SOURCEBASTION_VERSION", "").strip()
    if override:
        raw = override
        source = "SOURCEBASTION_VERSION"
    else:
        path = HERE / "VERSION"
        if not path.is_file():
            raise SystemExit(
                f"cannot determine the version: {path} is missing. The build "
                "context must include VERSION; set SOURCEBASTION_VERSION to "
                "build without it."
            )
        raw = path.read_text(encoding="utf-8").strip()
        source = str(path)
    if not re.fullmatch(r"\d+\.\d+\.\d+", raw):
        raise SystemExit(
            f"{source} must contain an exact MAJOR.MINOR.PATCH version, "
            f"got {raw!r}"
        )
    return raw


setup(
    name="sourcebastion-scanner",
    version=_release_version(),
    author="John Felten",
    author_email="jfelten.work@gmail.com",
    description="SourceBastion Scan - open-source application security scanning for GitHub and GitLab",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sourcebastion/sourcebastion-scanner",
    # Only the scanner. A bare `find_packages()` also swept in `api`, the
    # separate FastAPI deployable, because it has an `__init__.py` -- so every
    # scanner image shipped that service's code and, worse, claimed the
    # generic top-level name `api` in the image's import namespace. The API
    # image does not need it packaged: it copies `/app/api` and runs
    # `uvicorn api.main:app` from `WORKDIR /app`, resolving it from the
    # filesystem.
    packages=find_packages(include=["sourcebastion", "sourcebastion.*"]),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Security",
    ],
    python_requires=">=3.9",
    install_requires=[
        "packaging==26.3",
        "poetry-core==2.1.3",
        "click>=8.0",
        "jinja2>=3.1",
        "pydantic>=2.0",
        "pyyaml>=6.0",
        "requests>=2.28",
    ],
    package_data={
        "sourcebastion.inventory": [
            "node_selectors.cjs",
            "vendor/npm-semver-manifest.json",
            "vendor/npm-semver/*",
            "vendor/npm-semver/bin/*",
            "vendor/npm-semver/classes/*",
            "vendor/npm-semver/functions/*",
            "vendor/npm-semver/internal/*",
            "vendor/npm-semver/ranges/*",
        ],
        "sourcebastion": [
            "data/frameworks/*.json",
            "templates/*.j2",
        ],
    },
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "black>=23.0",
            "flake8>=6.0",
            "mypy>=1.0",
            "psutil>=5.9",
        ],
        "sql": [
            "sqlalchemy>=2.0",
        ],
        "metrics": [
            "prometheus_client>=0.20",
        ],
        "otel": [
            "opentelemetry-sdk>=1.25",
        ],
    },
    entry_points={
        "console_scripts": [
            "sourcebastion=sourcebastion.cli:main",
        ],
    },
)
