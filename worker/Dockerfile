# Worker = queue consumer + analyzer library + the analyzer toolchain (same pinned versions as
# scripts/setup.sh): Semgrep, Bandit, Node + ESLint (eslint-plugin-security), optional CodeQL.
#   docker compose build worker                              # without CodeQL (~1 GB smaller)
#   docker compose build --build-arg WITH_CODEQL=1 worker    # with the CodeQL bundle
FROM python:3.12-slim-bookworm

ARG SEMGREP_VERSION=1.186.0
ARG NODE_VERSION=22.23.5
ARG WITH_CODEQL=0
ARG CODEQL_VERSION=2.27.4

# git is required: the worker clones GitHub links via the analyzer's ingest.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl ca-certificates xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Semgrep in its own venv (it pins many dependencies)
RUN python -m venv /opt/sast \
    && /opt/sast/bin/pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}"

# Node + pinned ESLint toolchain (tools/eslint/package-lock.json)
RUN curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
      | tar -xJ -C /usr/local --strip-components=1
COPY tools/eslint/ /opt/eslint/
RUN cd /opt/eslint && npm ci --no-audit --no-fund

# CodeQL bundle (CLI + standard query packs), optional
RUN if [ "$WITH_CODEQL" = "1" ]; then \
      curl -fsSL "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.gz" \
        | tar -xz -C /opt; \
    fi

WORKDIR /srv
ENV PYTHONPATH=/srv \
    PIP_NO_CACHE_DIR=1 \
    PATH="/opt/sast/bin:/opt/codeql:${PATH}" \
    SECBENCH_ESLINT_HOME=/opt/eslint \
    SEMGREP_SEND_METRICS=off

COPY requirements.txt /srv/requirements.txt
RUN python -m pip install --quiet -r /srv/requirements.txt

COPY app /srv/app
COPY config /srv/config
COPY templates /srv/templates
COPY worker /srv/worker

CMD ["python", "-m", "worker"]
