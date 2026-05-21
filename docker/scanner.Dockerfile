# Sandbox image used to execute scanners (and the one-off git clone).
# Bakes Semgrep, Trivy, Gitleaks, CodeQL, and git. Vuln DBs / scanner bundles
# are baked at build time so scans can run with --network=none.
FROM python:3.12-slim AS base

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git tar gzip xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Semgrep (PyPI install)
RUN pip install --no-cache-dir "semgrep>=1.80"

# Trivy
ARG TRIVY_VERSION=0.70.0
RUN curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
      | tar -xz -C /usr/local/bin trivy \
    && trivy --version

# Pre-warm Trivy vuln DB so --network=none scans work.
RUN trivy --cache-dir /opt/trivy-cache image --download-db-only && \
    trivy --cache-dir /opt/trivy-cache image --download-java-db-only || true
ENV TRIVY_CACHE_DIR=/opt/trivy-cache

# Gitleaks
ARG GITLEAKS_VERSION=8.18.4
RUN curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks \
    && gitleaks version

# CodeQL CLI bundle. The worker keeps CodeQL opt-in with ENABLE_CODEQL=true
# because database creation/analysis is slower than the default scanner set.
ARG CODEQL_VERSION=2.17.6
RUN mkdir -p /opt/codeql \
    && curl -fsSL "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip" -o /tmp/codeql.zip \
    && python -m zipfile -e /tmp/codeql.zip /opt/codeql \
    && chmod -R +rx /opt/codeql/codeql \
    && chmod +x /opt/codeql/codeql/codeql \
    && ln -s /opt/codeql/codeql/codeql /usr/local/bin/codeql \
    && rm /tmp/codeql.zip \
    && codeql version

# A non-root user the runner switches to via --user.
RUN useradd -u 65534 -m -s /usr/sbin/nologin scanner || true

WORKDIR /work
USER 65534
