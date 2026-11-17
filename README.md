# repo-analyzer

Монолитный FastAPI-бэкенд для анализа исходного кода репозитория.

**Вход:** локальная папка / ZIP **или** ссылка на GitHub.  
**Выход:** отчёт по уязвимостям и черновик документации для ФСТЭК / личного пользования.  
**MVP:** обрабатывается только **Python**; обработчики языков модульные и включаются/выключаются в конфиге.

> Черновик ФСТЭК **не является** полным сертифицированным комплектом по приказу ФСТЭК России №76. Это исходник для ручной доработки.

## Быстрый старт

```bash
cd repo-analyzer
python -m venv .venv
# Windows:
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Swagger: http://127.0.0.1:8000/docs

## API (MVP)

1. Создать проект  
   - `POST /api/v1/projects` — `{ "source_type": "local_path", "local_path": "C:/path/to/repo" }`  
   - `POST /api/v1/projects` — `{ "source_type": "github", "github_url": "https://github.com/org/repo" }`  
   - `POST /api/v1/projects/upload` — multipart ZIP
2. Запустить скан: `POST /api/v1/projects/{id}/scans`
3. Забрать отчёты:
   - `GET /api/v1/projects/{id}/scans/{scan_id}/reports/security?format=markdown`
   - `GET /api/v1/projects/{id}/scans/{scan_id}/reports/security?format=json`
   - `GET /api/v1/projects/{id}/scans/{scan_id}/reports/fstec?format=markdown`

## Модульные языки

Файл [`config/settings.yaml`](config/settings.yaml):

```yaml
enabled_languages:
  - python
  # - javascript   # stub, пока не реализован
```

Контракт плагина: `app/languages/base.py` (`detect` / `analyze`).  
Python-хендлер: Bandit (SAST) + pip-audit (зависимости) + AST-инвентаризация.  
JavaScript: stub-заготовка для будущего подключения.

## Структура

```text
app/
  api/           # FastAPI routes
  languages/     # language plugins
  services/      # ingest, scan, reports
  models/        # pydantic models
config/settings.yaml
templates/       # Jinja2 отчёты
data/workspaces/ # артефакты проектов (gitignored)
```

## Тесты

```bash
pytest -q
```
