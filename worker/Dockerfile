FROM python:3.12-slim

# git is required: the worker clones GitHub links via the analyzer's ingest.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
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

CMD ["python", "-m", "worker"]
