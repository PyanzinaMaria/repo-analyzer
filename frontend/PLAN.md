# Merge Sirius26 frontend with repo-analyzer backend

## Context

The frontend (`D:\Sirius26`, FastAPI + Jinja2 + HTMX, 36 tests green) and the agent backend (`D:\Sirius26\repo-analyzer`, clone of `github.com/PyanzinaMaria/repo-analyzer`, branch `master`) were built independently around different contracts:

- **Frontend** is producer-agnostic: on submission it writes `data/queue/{scan_id}.json` and expects a producer to create `data/reports/{scan_id}/` with `manifest.json` (stages `analysis`/`report`), `summary.json` (`{"severities": {...}}`), `report.html`, `doc.html`. PDFs excluded per your decision — the frontend hides buttons for absent artifacts.
- **Backend** is an HTTP-only FastAPI service (synchronous scans: bandit + pip-audit + AST, optional AI) producing `security_report.json/.md` and `fstec_draft.md` under `data/workspaces/{project_id}/`. It knows nothing about the queue/manifest contract.

The merge therefore = **one repo layout + one new bridge component (producer worker)** that consumes queue jobs by calling the analyzer as a library and emits the frontend's file contract. Neither app's code changes.

**Decisions confirmed with you:** commit locally on a new `frontend` branch (no push — push command provided at the end for you to run); HTML-only artifacts (no PDFs).

## Target layout (branch `frontend` in `D:\Sirius26\repo-analyzer`)

```
repo-analyzer/                 ← branch frontend
├── app/  config/  templates/  tests/  requirements.txt   ← analyzer, UNTOUCHED (teammate's root layout preserved)
├── frontend/                  ← Sirius26 imported as-is (backend/, config/, i18n/, fixtures/, images/, README, PLAN, CLAIMS, .env.example)
├── worker/                    ← NEW producer bridge
├── docker-compose.yml         ← NEW combined (web + worker, shared ./data)
├── README.md                  ← updated: combined architecture + run instructions
└── .gitignore                 ← extended (frontend/data/, runtime dirs)
```

The original `D:\Sirius26` tree stays untouched as your frontend working copy. The frontend's `SIRIUS_APP_ROOT` auto-resolution (`parents[3]` of `config.py`) keeps working because `config/`, `i18n/`, `fixtures/` move together with `backend/` under `frontend/`. Worker imports the analyzer's root `app` package (separate processes, no `app` package-name collision with `frontend/backend/app`).

## Subtasks

**S1. Branch.** `git -C repo-analyzer checkout -b frontend` (from `master`).

**S2. Import frontend.** Copy into `frontend/`: `backend/`, `config/`, `i18n/`, `fixtures/`, `images/`, `README.md`, `PLAN.md`, `CLAIMS.md`, `.env.example`. Exclude `.venv/`, `data/`, `repo-analyzer/`, `.zcode/`. Extend `.gitignore` (`frontend/data/`, `*.claimed`). Replace `frontend/docker-compose.yml` with a root-level combined compose (web service reuses `frontend/backend/Dockerfile`, worker service is new `worker/Dockerfile`; both mount `./data`). Zero frontend code edits.

**S3. Worker bridge** (`worker/`, run as `python -m worker` from repo root):
- `config/worker.yaml` (nothing hardcoded): `data_dir: data`, `poll_interval_seconds`, `enable_ai: false`, timeouts. Pydantic-settings loader in the style of both apps.
- Queue consumer: poll `data/queue/*.json` sorted by `created_at`; claim atomically by renaming to `{scan_id}.claimed`; skip+delete jobs whose `data/uploads/{scan_id}/scan.json` no longer exists (retention edge case); delete the claimed file after a terminal manifest state.
- Pipeline per job:
  1. write `manifest.json` → `{"stages": {"analysis": "running", "report": "pending"}, "artifacts": []}` (never `intake` — frontend owns it)
  2. ingest via `app.services.ingest.IngestService` (`D:\Sirius26\repo-analyzer\app\services\ingest\__init__.py`): `kind: link` → `create_from_github(url)`; `kind: zip|files` → `create_from_local_path(data/uploads/{scan_id}/repo)` (payload already extracted by the frontend)
  3. `ScanOrchestrator.start_scan(project_id, enable_ai=cfg)` → `store.get_result(project_id, scan_id)` (`orchestrator.py:29`, `store.py:114`)
  4. manifest → `analysis: ok`, `report: running`
  5. render `report.html` (self-contained HTML: inline-SVG severity donut using frontend theme colors, findings cards with file/line/CWE/remediation, AI meta) and `doc.html` (ФСТЭК-style doc from the result inventory) — new Jinja2 templates in `worker/templates/`, Russian strings, sandboxed-iframe-safe (no external resources)
  6. write `summary.json` → `{"severities": {by_severity}}` with analyzer severities mapped to the frontend's `theme.yaml` keys (`critical/high/medium/low/info`; `unknown` → `info`)
  7. manifest → `artifacts: [report.html, doc.html]`, `report: ok`; claim file deleted
  8. any exception → current stage `fail` in manifest, claim file deleted (frontend stops polling and shows «Ошибка»)
- Worker tests (offline; ingest/orchestrator monkeypatched, fixture `ScanResult`): claim semantics, manifest transitions, severity mapping, artifact files written, fail path.

**S4. Environment.** Install analyzer deps into the existing `D:\Sirius26\.venv` (`bandit`, `pip-audit`, `pytest-asyncio` + `requirements.txt` ranges — compatible with the frontend's exact pins: fastapi/uvicorn/httpx/jinja2/pydantic all satisfy).

**S5. Root README + compose** (combined architecture diagram, run instructions for web + worker, env vars, contract description).

## Verification (S6 — "check everything together")

1. Frontend: `cd repo-analyzer/frontend/backend && D:\Sirius26\.venv\Scripts\python -m pytest` → 36 passed; `ruff check app tests` clean.
2. Analyzer: `cd repo-analyzer && pytest -q` → 4 test files (note: `test_scan_local.py` and `test_pip_audit.py` need network for pip-audit; I'll report if blocked).
3. Worker tests green.
4. E2E manual run (no Docker locally): start web with `SIRIUS_DATA_DIR=<repo>\data` on :8000 and `python -m worker` alongside; then via browser:
   - submit a small public GitHub repo link → status page shows `intake ok → analysis running → ok → report ok`, donut renders, `report.html`/`doc.html` open in sandboxed viewers
   - upload a zip of a tiny Python project → same flow
   - negative: bad repo URL → `analysis: fail` badge, polling stops
5. Compose file inspected only (no Docker on this machine) — stated as unverified.

## Commits (local, on `frontend`)

1. `Import Sirius26 frontend into frontend/`
2. `Add producer worker bridging the queue contract to the analyzer`
3. `Add combined compose, README, gitignore`

Push is **not** executed (your choice). When ready:
```
git -C D:\Sirius26\repo-analyzer push -u origin frontend
```
(origin `git@github.com:PyanzinaMaria/repo-analyzer.git` requires your write access; an open PR against `master` is the natural follow-up for the team.)