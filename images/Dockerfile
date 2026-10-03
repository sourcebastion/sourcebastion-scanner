# Pull kics binary from official image
FROM checkmarx/kics@sha256:3e5a268eb8adda2e5a483c9359ddfc4cd520ab856a7076dc0b1d8784a37e2602 as kics

# Multi-stage build for minimal image size (pinned versions to satisfy hadolint)
FROM python:3.11.9-alpine3.18 as builder

SHELL ["/bin/ash", "-o", "pipefail", "-c"]

RUN apk add --no-cache \
    gcc=12.2.1_git20220924-r10 \
    musl-dev=1.2.4-r3 \
    libffi-dev=3.4.4-r2 \
    openssl-dev=3.1.8-r0 \
    git=2.40.4-r0

WORKDIR /app


# Copy and build wheel
COPY . /app
RUN python scripts/scanner_artifacts.py install --libc musl --group build && \
    python -m build --no-isolation --wheel --outdir /dist


FROM alpine:3.18

SHELL ["/bin/ash", "-o", "pipefail", "-c"]

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install runtime dependencies (pinned versions)
RUN apk add --no-cache \
    python3=3.11.12-r1 \
    git=2.40.4-r0 \
    openssh-client=9.3_p2-r3 \
    curl=8.12.1-r0 \
    bash=5.2.15-r5 \
    ca-certificates=20241121-r1 \
    libffi=3.4.4-r2 \
    openssl=3.1.8-r0 \
    nodejs=18.20.1-r0 \
    npm=9.6.6-r0 && \
    python3 -m ensurepip

# Install scanners with explicit versions or static binaries
RUN ARCH=$(uname -m) && \
    case "$ARCH" in \
      aarch64) GL_ARCH="arm64"; GL_SHA256="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080" ;; \
      x86_64)  GL_ARCH="x64";  GL_SHA256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" ;; \
      *) echo "Unsupported arch: $ARCH" && exit 1 ;; \
    esac && \
    curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_${GL_ARCH}.tar.gz" \
      -o /tmp/gitleaks.tar.gz && \
    echo "${GL_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    rm /tmp/gitleaks.tar.gz && \
    chmod +x /usr/local/bin/gitleaks && \
    gitleaks version

RUN ARCH=$(uname -m) && \
    case "$ARCH" in \
      aarch64) GRYPE_ARCH="arm64"; GRYPE_SHA256="29f0ec7c549ddb0e2b6a0ca714851f7399438afc399b80c12808e065edc9a8f8" ;; \
      x86_64)  GRYPE_ARCH="amd64"; GRYPE_SHA256="3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b" ;; \
      *) echo "Unsupported arch: $ARCH" && exit 1 ;; \
    esac && \
    curl -sSfL "https://github.com/anchore/grype/releases/download/v0.119.0/grype_0.119.0_linux_${GRYPE_ARCH}.tar.gz" \
      -o /tmp/grype.tar.gz && \
    echo "${GRYPE_SHA256}  /tmp/grype.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/grype.tar.gz -C /usr/local/bin grype && \
    rm /tmp/grype.tar.gz && \
    chmod +x /usr/local/bin/grype && \
    grype version

# Install only the reviewed, hash-verified Semgrep wheel.
COPY scripts/scanner_artifacts.py /opt/sourcebastion/scanner_artifacts.py
COPY .github/semgrep-artifacts.json .github/scanner-versions.json /opt/sourcebastion/
COPY .github/python-locks /opt/sourcebastion/python-locks
RUN python3 /opt/sourcebastion/scanner_artifacts.py install --libc musl \
      --lock /opt/sourcebastion/semgrep-artifacts.json --pins /opt/sourcebastion/scanner-versions.json \
      --dependencies /opt/sourcebastion/python-locks && \
    semgrep --version && \
    find /usr/lib/python3.11/site-packages -depth -type d -name __pycache__ -exec rm -rf {} + && \
    rm -rf /usr/lib/python3.11/ensurepip

# Bundle GitLab SAST rules (language dirs only — offline use, richer severity metadata)
RUN curl -sSfL "https://gitlab.com/gitlab-org/security-products/sast-rules/-/archive/main/sast-rules-main.tar.gz" \
      -o /tmp/sast-rules.tar.gz && \
    mkdir -p /tmp/sast-rules-extract /usr/local/share/sast-rules && \
    tar -xzf /tmp/sast-rules.tar.gz -C /tmp/sast-rules-extract && \
    for lang in c csharp go java javascript python scala; do \
      mv "/tmp/sast-rules-extract/sast-rules-main/$lang" /usr/local/share/sast-rules/; \
    done && \
    rm -rf /tmp/sast-rules.tar.gz /tmp/sast-rules-extract && \
    curl -sSfL "https://semgrep.dev/c/p/ruby" -o /usr/local/share/sast-rules/ruby.yml

# Copy kics binary and assets from official image
COPY --from=kics /app/bin/kics /usr/local/bin/kics
COPY --from=kics /app/bin/assets /usr/local/bin/assets
RUN kics version

# Install SourceBastion scanner wheel and dependencies from builder
COPY --from=builder /dist/*.whl /tmp/
# `python3 -m pip` rather than bare `pip`: this stage provisions pip with
# `python3 -m ensurepip`, which installs `pip3` and `pip3.11` but no plain
# `pip`. The console script came from a `pip install --upgrade pip` line
# that was removed when the dependency trees were locked, so bare `pip`
# became `not found` (exit 127) and every image build failed.
RUN python3 -m pip install --no-cache-dir --no-index --no-deps /tmp/*.whl && python3 -m pip check && \
    rm /tmp/*.whl && \
    find /usr/lib/python3.11/site-packages -depth -type d -name __pycache__ -exec rm -rf {} + && \
    rm -rf /usr/lib/python3.11/ensurepip

ENV PATH="/usr/local/bin:/usr/bin:/bin:$PATH"

# Copy custom SAST rule packs
COPY rules/ /app/rules/

# Create non-root user for runtime
RUN addgroup -S ezappsec && adduser -S -G ezappsec ezappsec && \
    mkdir -p /scan /home/ezappsec/.cache && \
    chown -R ezappsec:ezappsec /web /app/rules /home/ezappsec /scan

USER ezappsec
ENV HOME=/home/ezappsec

WORKDIR /scan

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD sourcebastion --version || exit 1

# Default command
ENTRYPOINT ["sourcebastion"]
CMD ["--help"]
