# DAST sandbox

Intentionally vulnerable HTTP targets for local DAST development.
Only stacks that match current `enabled_languages` are shipped here (Python).

## Start target

```bash
docker compose -f sandbox/dast/docker-compose.yml up --build -d
```

Target: http://127.0.0.1:8001/

Known weak spots: missing security headers, reflected XSS at `/search?q=`,
weak cookie at `/set-cookie`, permissive CORS, public `/docs` + `/openapi.json`.

## Run DAST via analyzer API

```bash
# from repo root, with venv active and allow_private_targets: true in config/settings.yaml
uvicorn app.main:app --port 8000
```

```bash
curl -X POST http://127.0.0.1:8000/api/v1/dast/scans \
  -H "Content-Type: application/json" \
  -d "{\"target_url\":\"http://127.0.0.1:8001/\"}"
```

Then `GET /api/v1/dast/scans/{id}/result`.

## Run via worker queue

Write `data/queue/{scan_id}.json`:

```json
{
  "scan_id": "11111111111111111111111111111111",
  "source": {
    "kind": "dast",
    "target_url": "http://127.0.0.1:8001/"
  }
}
```

Worker writes `data/reports/{scan_id}/` including `dast_report.json`, `summary.json`, `report.html`.

ZAP baseline runs in Docker; `127.0.0.1` / `localhost` targets are rewritten to
`host.docker.internal` automatically so the scanner container can reach the
published sandbox port.

## Stop

```bash
docker compose -f sandbox/dast/docker-compose.yml down
```
