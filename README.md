# Аудитор кода — монорепозиторий

Полный конвейер анализа репозиториев: веб-фронтенд приёма заявок, продюсер-воркер
и анализатор (Bandit + pip-audit + AST, опционально ИИ). Ветка `frontend`
объединяет фронтенд и бэкенд; связь между сервисами — **только файловый контракт**
через общее дерево `data/`, никакого прямого HTTP между ними нет.

```
Браузер ──HTTP──▶ WEB :8000 ──пишет──▶ data/uploads/{id}/  +  data/queue/{id}.json
                                             │
WORKER ──поллинг queue/──▶ CLAIM (rename .claimed)
   │  вызывает библиотеку ANALYZATOR (IngestService → ScanOrchestrator)
   │  bandit / pip-audit / AST — субпроцессы; GitHub-ссылки клонируются (git --depth 1)
   ▼
data/reports/{id}/  ◀──пишет WORKER──  manifest.json · summary.json · report.html · doc.html
                                             │
Браузер ◀──HTMX-поллинг /scan/{id}/body── WEB читает manifest/summary и раздаёт артефакты
```

- **Веб-фронтенд** (`frontend/`) — приём репозитория (zip / файлы / ссылка GitHub-GitLab),
  защита от zip-бомб на входе, страница статуса, просмотр и скачивание готовых артефактов.
  Подробнее: [`frontend/README.md`](frontend/README.md).
- **Воркер** (`worker/`) — продюсер: забирает задачи из `data/queue/`, запускает анализ,
  рендерит `report.html` (отчёт аудита) и `doc.html` (черновик ФСТЭК), пишет
  `summary.json` (donut-виджет) и `manifest.json` (этапы статуса).
- **Анализатор** (`app/`) — библиотека для воркера и самостоятельный HTTP-сервис
  (`/api/v1/...`) для отладки; оригинальные README-разделы ниже.

## Файловый контракт (единственная точка интеграции)

| Дерево | Кто пишет | Кто читает |
|---|---|---|
| `data/queue/{scan_id}.json` | web (при подаче заявки) | worker (забирает rename'ом в `.claimed`) |
| `data/uploads/{scan_id}/repo/` | web (распакованный payload) | worker (для zip/файлов; клонирование — на воркере) |
| `data/reports/{scan_id}/manifest.json` | worker: `stages: {analysis, report}` | web: слияние со статусом + HTMX-поллинг |
| `data/reports/{scan_id}/summary.json` | worker: `{"severities": {...}}` | web: donut-виджет |
| `data/reports/{scan_id}/report.html`, `doc.html` | worker | web: sandboxed iframe + скачивание |
| `data/workspaces/{project_id}/` | анализатор (своё хранилище) | — |

Этап `intake` принадлежит веб-фронтенду и в манифестах воркера не участвует.
При сбое воркер помечает `fail` текущий и все последующие этапы — страница статуса
останавливает поллинг только когда все этапы терминальны.

## Быстрый старт (без Docker, два процесса)

Требования: Python 3.11+, git (для клонирования ссылок), сеть для pip-audit и GitHub.

```bash
# Windows; venv один на всё
py -3.12 -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\pip install -r frontend\web\requirements.lock

# 1) веб-фронтенд
set SIRIUS_DATA_DIR=%cd%\data
.venv\Scripts\python -m uvicorn app.main:app --app-dir frontend\web --port 8000

# 2) воркер (второй терминал, из корня репозитория)
.venv\Scripts\python -m worker
```

Открыть http://127.0.0.1:8000/ , подать репозиторий (ссылка или zip) — статус,
отчёт и документация появятся автоматически после завершения анализа.

Linux/macOS: те же команды с `python3 -m venv .venv`, `export SIRIUS_DATA_DIR=$PWD/data`,
пути `frontend/web` через `/`.

## Docker

```bash
docker compose up --build
```

Два сервиса: `web` (:8000) и `worker`, общий volume `./data`. Конфиг воркера —
`worker/config/worker.yaml`, переопределения через env: `WORKER_DATA_DIR`,
`WORKER_POLL_INTERVAL_SECONDS`, `WORKER_ENABLE_AI` (+ `AI_API_KEY` для ИИ-анализа).

## Содержание

- [Быстрый старт](#быстрый-старт-без-docker-два-процесса)
- [Файловый контракт](#файловый-контракт-единственная-точка-интеграции)
- [Анализатор: API](#анализатор-api)
- [Анализатор: языковые плагины](#языковые-плагины)
- [Анализатор: ИИ-анализ](#ии-анализ)
- [Структура](#структура)
- [Тесты](#тесты)

---

## Анализатор: API

Сервис запускается отдельно для отладки (`uvicorn app.main:app --port 8000`, Swagger `/docs`).
Воркер использует те же классы напрямую как библиотеку.

| Источник | Запрос |
|---|---|
| Локальный путь | `POST /api/v1/projects` → `{"source_type":"local_path","local_path":"C:/path/to/repo"}` |
| GitHub | `POST /api/v1/projects` → `{"source_type":"github","github_url":"https://github.com/org/repo"}` |
| ZIP | `POST /api/v1/projects/upload` — multipart |

Скан: `POST /api/v1/projects/{id}/scans` (тело необязательно; `{"enable_ai": true}` — ИИ на этот скан).
Отчёты: `GET …/reports/security?format=markdown|json`, `GET …/reports/fstec?format=markdown`.
Результат целиком: `GET /api/v1/projects/{id}/scans/{scan_id}/result`.

> Черновик ФСТЭК **не является** полным сертифицированным комплектом по приказу №76.

## Языковые плагины

В [`config/settings.yaml`](config/settings.yaml):

```yaml
enabled_languages:
  - python
  # - javascript   # stub, пока не реализован
```

- Контракт: [`app/languages/base.py`](app/languages/base.py) — `detect` / `analyze`.
- **Python:** Bandit + pip-audit + инвентаризация модулей/классов/функций/импортов.

## ИИ-анализ

Post-scan review отобранных файлов через OpenAI-compatible API, `source=ai` у находок.
Не заменяет Bandit/pip-audit; ошибка LLM не валит скан.

1. `ai.enabled: true` в [`config/settings.yaml`](config/settings.yaml) (или `WORKER_ENABLE_AI=true` у воркера)
2. `AI_API_KEY=…` (обязательно), опционально `AI_BASE_URL`, `AI_MODEL`

Без ключа модуль тихо пропускается (`meta.ai.status=skipped`).

## Структура

```text
app/              # анализатор (библиотека + HTTP-сервис)
config/           # settings.yaml анализатора
templates/        # Jinja2 markdown-шаблоны анализатора
worker/           # продюсер: queue → analyzer → отчёты фронтенду
  config/worker.yaml
  templates/      # report.html.j2, doc.html.j2
frontend/         # веб-фронтенд (см. frontend/README.md)
data/             # runtime: queue/ uploads/ reports/ workspaces/ (gitignored)
```

## Тесты

```bash
.venv/Scripts/python -m pytest worker/tests -q                  # воркер (офлайн)
cd frontend/web && ../../.venv/Scripts/python -m pytest     # фронтенд, 37 тестов
pytest -q                                                       # анализатор (pip-audit требует сеть)
```
