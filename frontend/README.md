# Аудитор кода — фронтенд

Web frontend for the code security audit service. It accepts repository
submissions (zip archive, individual files, folder, public GitHub/GitLab
link), tracks scan status, and serves ready report files produced by other
tasks. It does **not** implement the AI agent, agent communication, or
report/documentation generation.

## Run locally

```bash
py -3.14 -m venv .venv                 # or python 3.12+
.venv/Scripts/pip install -r web/requirements.lock   # Windows
.venv/Scripts/python -m uvicorn app.main:app --app-dir web --port 8000
```

Open http://127.0.0.1:8000/

## Run in Docker

From the repository root (the combined compose file lives there and starts
both the web service and the producer worker):

```bash
docker compose up --build
```

The compose file mounts `./data` into both services, so the worker drops
ready reports into `data/reports` without a rebuild.

## Demo data

A placeholder producer output is bundled in `fixtures/demo-scan/`. To see the
full flow (status, donut chart, document buttons, PDF downloads) without real
producers:

```bash
mkdir -p data/uploads data/reports
cp -r fixtures/demo-scan/uploads/. data/uploads/
cp -r fixtures/demo-scan/reports/. data/reports/
```

Then open http://127.0.0.1:8000/scan/00000000-0000-0000-0000-000000000001

## Tests

```bash
cd web && ../.venv/Scripts/python -m pytest
../.venv/Scripts/python -m ruff check app tests   # from web/
```

37 tests cover the zip guard (bombs, traversal, symlinks, limits), intake
validation, form engine, API contract, and artifact serving.

## Configuration (nothing hardcoded)

| File | Contents |
|---|---|
| `config/app.yaml` | title, storage layout, retention, server, body limit |
| `config/upload.yaml` | intake limits, forbidden segments, extension whitelist, manifest patterns |
| `config/reports.yaml` | producer contract: artifact names, labels, MIME, viewer mode, stage list |
| `config/theme.yaml` | bimbo pink palette; regenerated into `static/css/theme.css` at startup |
| `config/forms/*.yaml` | declarative form definitions (goal 9) |
| `i18n/ru.yaml` | all Russian UI strings |

Environment overrides (`SIRIUS_*`, see `.env.example`): title, base URL,
data dir, host/port, max body bytes.

## File contract for producer tasks

This is the only integration point. The frontend never writes into
`data/reports/`; producers own that tree.

**Input handoff:** when a client submits a scan, the registry writes
`data/queue/{scan_id}.json`:

```json
{
  "scan_id": "<uuid>",
  "created_at": "2026-11-17T12:00:00+00:00",
  "source": {"kind": "link", "url": "https://github.com/owner/repo"}
}
```

`kind` is `link` (payload absent — cloning is the producer's job), `zip` or
`files` (payload extracted under `data/uploads/{scan_id}/repo/`).

Failed intake scans are withdrawn: the queue job is deleted and
`data/uploads/{scan_id}/scan.json` records `"error": "<zip-guard code>"`.

**Output:** producers create `data/reports/{scan_id}/` with:

| File | Required | Purpose |
|---|---|---|
| `manifest.json` | yes | living status document (below) |
| `summary.json` | for the donut widget | `{"severities": {"critical": 1, "high": 3, ...}}` |
| `report.html` | optional | audit report, served sandboxed |
| `doc.html` | optional | ФСТЭК documentation, served sandboxed |
| `report.pdf`, `doc.pdf` | optional | downloadable versions |

`manifest.json` schema (stages come from `config/reports.yaml`; only report
progress is meaningful to producers — `intake` is owned by the frontend):

```json
{
  "stages": {"analysis": "running", "report": "pending"},
  "artifacts": ["report.html", "report.pdf"]
}
```

Stage states: `pending`, `running`, `ok`, `fail`. The scan page polls the
manifest until every stage reaches `ok`/`fail` and enables buttons only for
artifacts listed there and present on disk.

Serving safety: artifact HTML is delivered with
`Content-Security-Policy: sandbox allow-scripts` and displayed inside a
sandboxed iframe; scan ids are validated as UUIDs on every route.

## Form reuse (goal 9)

To adapt the frontend to another application, add
`config/forms/<new_id>.yaml` (field types: text, url, radio, select,
file-multi, folder; i18n label keys; visibility conditions; validators) —
the generic macro renders it without any HTML or Python changes. For program
control, subclass `app.ui.engine.Form` and override `form_id` or validation.

## Known limitations

- No authentication (MVP decision).
- The body limit checks the declared Content-Length; chunked uploads without
  it are bounded only by intake quotas.
- Retention cleanup runs at startup only (`retention_days` in app.yaml).
