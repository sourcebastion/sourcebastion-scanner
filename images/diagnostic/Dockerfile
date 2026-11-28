# M066 S01/T05: the probe-diagnostic image. Built FROM an exact release digest
# and used only for S01's forced probe_timeout case; never a default image.
ARG RELEASE_IMAGE
FROM ${RELEASE_IMAGE}
COPY --chmod=0555 images/diagnostic/opengrep /opt/diagnostic/bin/opengrep
ENV PATH="/opt/diagnostic/bin:${PATH}"
LABEL org.opencontainers.image.title=sourcebastion-scanner-diagnostic \
      org.opencontainers.image.description="SourceBastion scanner with a slow opengrep --version, for probe_timeout diagnostics only"
