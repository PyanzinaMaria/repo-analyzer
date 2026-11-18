FROM python:3.12-slim

# git is required: the worker clones GitHub links via the analyzer's ingest.
# Pango/GObject + fonts are required by the WeasyPrint PDF engine; DejaVu
# covers Cyrillic (the FSTEC document language).
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
       libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf-2.0-0 \
       fontconfig fonts-dejavu-core \
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
# Producer-side contract: method catalog, models and documents x formats
# (worker/config.py loads frontend/config/{analysis,reports}.yaml).
COPY frontend/config /srv/frontend/config

CMD ["python", "-m", "worker"]
