# syntax=docker/dockerfile:1
# check=error=true
ARG PYTHON_VERSION=3.14.8
FROM python:${PYTHON_VERSION}-alpine3.23 AS python-base

FROM checkmarx/kics@sha256:3e5a268eb8adda2e5a483c9359ddfc4cd520ab856a7076dc0b1d8784a37e2602 AS kics

# Based on the smallest published (micro) image: Alpine and a copied virtualenv.
# Wheel-only dependency installs need no compiler or development headers.
FROM python-base AS builder
ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY . /app
RUN python scripts/scanner_artifacts.py install --libc musl --group build && \
    python -m build --no-isolation --wheel --outdir /dist && \
    python -m venv /opt/venv && \
    /opt/venv/bin/python scripts/scanner_artifacts.py install --libc musl && \
    /opt/venv/bin/python -m pip install --no-cache-dir --no-index --no-deps /dist/*.whl && \
    /opt/venv/bin/python -m pip check && \
    find /opt/venv -type d -name __pycache__ -prune -exec rm -rf {} +

# Downloads, extraction tools, build context and wheel files stay in this stage.
FROM python-base AS scanners
RUN apk add --no-cache ca-certificates curl
SHELL ["/bin/ash", "-o", "pipefail", "-c"]
COPY scripts/download_scanners.py .github/scanner-versions.json /tmp/scanners/
RUN python /tmp/scanners/download_scanners.py --pins /tmp/scanners/scanner-versions.json
RUN curl -sSfL "https://gitlab.com/gitlab-org/security-products/sast-rules/-/archive/main/sast-rules-main.tar.gz" \
      -o /tmp/sast-rules.tar.gz && \
    mkdir -p /tmp/sast-rules-extract /usr/local/share/sast-rules && \
    tar -xzf /tmp/sast-rules.tar.gz -C /tmp/sast-rules-extract && \
    for lang in c csharp go java javascript python scala; do \
      mv "/tmp/sast-rules-extract/sast-rules-main/$lang" /usr/local/share/sast-rules/; \
    done && \
    curl -sSfL "https://semgrep.dev/c/p/ruby" -o /usr/local/share/sast-rules/ruby.yml

FROM python-base AS runtime
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH"
# npm and pip support project dependency discovery. No curl or build toolchain.
RUN apk add --no-cache git openssh-client ca-certificates nodejs npm bash libffi openssl libstdc++
COPY --from=builder /opt/venv /opt/venv
COPY --from=scanners /usr/local/bin/gitleaks /usr/local/bin/grype /usr/local/bin/
COPY --from=scanners /usr/local/share/sast-rules /usr/local/share/sast-rules
COPY --from=kics /app/bin/kics /usr/local/bin/kics
COPY --from=kics /app/bin/assets /usr/local/bin/assets
COPY rules/ /app/rules/
RUN addgroup -S sourcebastion && adduser -S -G sourcebastion sourcebastion && \
    mkdir -p /scan /home/sourcebastion/.cache && \
    chown -R sourcebastion:sourcebastion /home/sourcebastion /scan
USER sourcebastion
ENV HOME=/home/sourcebastion
WORKDIR /scan
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD sourcebastion --version || exit 1
ENTRYPOINT ["sourcebastion"]
CMD ["--help"]
