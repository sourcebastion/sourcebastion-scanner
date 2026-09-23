from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ez-appsec",
    version="0.1.0",
    author="John Felten",
    author_email="jfelten.work@gmail.com",
    description="SourceBastion Scan - open-source application security scanning for GitHub and GitLab",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sourcebastion/sourcebastion-scanner",
    packages=find_packages(),
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
        "click>=8.0",
        "jinja2>=3.1",
        "openai>=1.0",
        "pydantic>=2.0",
        "pyyaml>=6.0",
        "requests>=2.28",
    ],
    package_data={
        "ez_appsec": [
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
            "ez-appsec=ez_appsec.cli:main",
        ],
    },
)
