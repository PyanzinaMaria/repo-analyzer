FROM python:3.12-slim

WORKDIR /srv
ENV PYTHONPATH=/srv/backend \
    SIRIUS_APP_ROOT=/srv \
    PIP_NO_CACHE_DIR=1

COPY backend/requirements.lock /srv/backend/requirements.lock
RUN python -m pip install --quiet -r /srv/backend/requirements.lock

COPY backend/app /srv/backend/app
COPY config /srv/config
COPY i18n /srv/i18n

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
