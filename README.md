# repo-analyzer

FastAPI-сервис, который берёт репозиторий и за один прогон отдаёт отчёт по уязвимостям плюс черновик материалов для ФСТЭК. Языки и ИИ-анализ подключаются флагами в конфиге — без переписывания пайплайна.

- **Вход.** Локальная папка, ZIP или ссылка на GitHub.
- **Выход.** Security-отчёт (JSON/Markdown) и черновик документации ФСТЭК.
- **Python из коробки.** Bandit (SAST) + pip-audit (зависимости) + AST-инвентаризация.
- **Модульные языки.** Вкл/выкл в `config/settings.yaml`; контракт плагина — `detect` / `analyze`.
- **Опциональный ИИ.** Post-scan review отобранных файлов через OpenAI-compatible API; ошибка LLM не валит скан.

```bash
# 1) проект из локальной папки
curl -s -X POST http://127.0.0.1:8000/api/v1/projects \
  -H "Content-Type: application/json" \
  -d "{\"source_type\":\"local_path\",\"local_path\":\"C:/path/to/repo\"}"
# => {"id":"…","status":"ready",…}

# 2) скан
curl -s -X POST http://127.0.0.1:8000/api/v1/projects/{id}/scans
# => {"id":"…","status":"completed","findings_count":N,…}

# 3) отчёт
curl -s "http://127.0.0.1:8000/api/v1/projects/{id}/scans/{scan_id}/reports/security?format=markdown"
# => Markdown с находками Bandit / pip-audit / (опционально) ai
```

> Черновик ФСТЭК **не является** полным сертифицированным комплектом по приказу №76. Это исходник для ручной доработки.

---

## Содержание

- [Быстрый старт](#быстрый-старт)
- [API](#api)
- [Языковые плагины](#языковые-плагины)
- [ИИ-анализ](#ии-анализ)
- [Структура](#структура)
- [Тесты](#тесты)

---

## Быстрый старт

Требования: Python 3.11+ (рекомендуется), доступ в сеть для GitHub-ingest и pip-audit.

```bash
cd repo-analyzer
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
# source .venv/bin/activate

pip install -r requirements.txt
copy .env.example .env   # или: cp .env.example .env
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Откройте Swagger: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

Проверка живости:

```bash
curl -s http://127.0.0.1:8000/health
# => {"status":"ok","enabled_languages":["python"],…}
```

---

## API

### 1. Создать проект

| Источник | Запрос |
|---|---|
| Локальный путь | `POST /api/v1/projects` → `{"source_type":"local_path","local_path":"C:/path/to/repo"}` |
| GitHub | `POST /api/v1/projects` → `{"source_type":"github","github_url":"https://github.com/org/repo"}` |
| ZIP | `POST /api/v1/projects/upload` — multipart |

### 2. Запустить скан

```http
POST /api/v1/projects/{id}/scans
```

Тело необязательно. Чтобы включить/выключить ИИ только на этот скан:

```json
{ "enable_ai": true }
```

### 3. Забрать отчёты

| Отчёт | URL |
|---|---|
| Security Markdown | `GET …/reports/security?format=markdown` |
| Security JSON | `GET …/reports/security?format=json` |
| Черновик ФСТЭК | `GET …/reports/fstec?format=markdown` |

Результат скана целиком: `GET /api/v1/projects/{id}/scans/{scan_id}/result`.

---

## Языковые плагины

В [`config/settings.yaml`](config/settings.yaml):

```yaml
enabled_languages:
  - python
  # - javascript   # stub, пока не реализован
```

- Контракт: [`app/languages/base.py`](app/languages/base.py) — `detect` / `analyze`.
- **Python:** Bandit + pip-audit + инвентаризация модулей/классов/функций/импортов.
- **JavaScript:** заготовка под будущее подключение.

---

## ИИ-анализ

Отдельный слой после языковых сканеров. LLM смотрит отобранные файлы и добавляет findings с `source=ai`. Не заменяет Bandit/pip-audit.

**Включение**

1. `ai.enabled: true` в [`config/settings.yaml`](config/settings.yaml)
2. `AI_API_KEY=…` в `.env` (обязательно)
3. Опционально: `AI_BASE_URL`, `AI_MODEL`, `AI_ENABLED`

Без ключа или при `ai.enabled: false` модуль тихо пропускается (`meta.ai.status=skipped`). Ошибка API не роняет скан (`status=failed` только у ИИ-блока).

```yaml
ai:
  enabled: false
  provider: openai_compatible
  base_url: https://api.openai.com/v1
  model: gpt-4o-mini
  timeout_seconds: 120
  max_files: 25
  max_file_bytes: 40000
  max_findings: 50
```

---

## Структура

```text
app/
  api/           # FastAPI routes
  ai/            # optional LLM code review
  languages/     # language plugins
  services/      # ingest, scan, reports
  models/        # pydantic models
config/settings.yaml
templates/       # Jinja2 отчёты
data/workspaces/ # артефакты проектов (gitignored)
```

---

## Тесты

```bash
pytest -q
```
