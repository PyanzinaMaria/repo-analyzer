FROM python:3.12-slim

# git is required: the worker clones GitHub links via the analyzer's ingest.
# Pango/GObject + fonts are required by the WeasyPrint PDF engine; DejaVu
# covers Cyrillic (the FSTEC document language).
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
       libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf-2.0-0 \
       fontconfig fonts-dejavu-core ca-certificates curl gnupg \
    && rm -rf /var/lib/apt/lists/*

# Docker CLI + compose plugin (daemon not included): the DAST sandbox shells
# out to `docker` / `docker compose` to boot scan targets and run ZAP against
# the socket mounted in compose. Without the plugin, repos with a compose
# file fail to boot ("unknown shorthand flag: 'f' in -f").
RUN install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" \
       > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
ENV PYTHONPATH=/srv \
    PIP_NO_CACHE_DIR=1

COPY requirements.txt /srv/requirements.txt
RUN python -m pip install --quiet -r /srv/requirements.txt

COPY app /srv/app
COPY config /srv/config
COPY templates /srv/templates
COPY worker /srv/worker
# System prompts for the LLM final documents (worker.yaml ai_documents:
# references system_prompts/FSTEC.md and CODE_DOCUMENTATION.md).
COPY system_prompts /srv/system_prompts
# Producer-side contract: method catalog, models and documents x formats
# (worker/config.py loads frontend/config/{analysis,reports}.yaml).
COPY frontend/config /srv/frontend/config

CMD ["python", "-m", "worker"]
