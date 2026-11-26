# Спецификация: аудитор репозиториев (handoff)

Документ для передачи: что это за система, какие контракты нельзя ломать, как поднять окружение и как проверить, что всё работает. Смысл для пользователя — в [`process.md`](process.md); здесь — инженерная спецификация.

**Базовая линия после интеграции:** `feature/secaudit-integrate` (+ влитый `feature/ai-final-docs`).  
**Правило:** secaudit = реализация runners `static` / `ai` внутри уже существующего UI. Новые кнопки отчётов и отдельный UI под secaudit **не вводить**. Опциональные LLM-доки `fstec` / `codedocs` — только через `worker.yaml` / `WORKER_ENABLE_AI_DOCUMENTS`, не через новые кнопки методов.

---

## 1. Цель продукта

Принять репозиторий (GitHub/GitLab URL или zip/файлы), по галочкам прогнать выбранные методы анализа и выдать:

1. **Отчёт аудита** — единый документ с секциями по методам (SAST / LLM / DAST).
2. **Документацию ФСТЭК** — черновик по тому же результату.

Оба документа — только в **выбранных форматах** (md / html / pdf / docx).

Отдельной кнопки «Отчёт DAST» / `audit_report` в UI **нет**. Служебные файлы (`secaudit/`, `audit_report.md`, SARIF, ranking) лежат рядом с отчётом на диске и **не** публикуются как serveable-артефакты.

---

## 2. Архитектура (три процесса, один `data/`)

```
Браузер ──HTTP──▶ WEB :8000 ──▶ data/uploads/{id}/ + data/queue/{id}.json
                                      │
WORKER ──поллинг queue/──▶ claim (.claimed)
   │  IngestService → ScanOrchestrator (библиотека app/)
   ▼
data/reports/{id}/  ◀── manifest.json · summary.json · report.* · doc.*
                                      │
Браузер ◀── HTMX /scan/{id} ── WEB читает reports/
```

| Компонент | Путь | Роль |
|---|---|---|
| Web | `frontend/web` | Форма, intake, статус, раздача артефактов |
| Worker | `worker/` | Очередь, анализ, рендер отчётов |
| Analyzer | `app/` | SAST / context / LLM / DAST / sandbox |

Связь web↔worker — **только файлы** в общем `data/`.  
Конфиг фронта: `frontend/config/app.yaml` → `data_dir: ../data` (общий с воркером).  
Переопределения: `SIRIUS_DATA_DIR` / `WORKER_DATA_DIR` — **обязательно один и тот же абсолютный путь**.  
Если web пишет в `frontend/data/`, а worker читает `data/`, заявки «зависают» после intake. Прямого HTTP между сервисами нет.

---

## 3. Жёсткий контракт UI ↔ pipeline

### 3.1 Методы формы → runners

Источник выбора: [`frontend/config/analysis.yaml`](../frontend/config/analysis.yaml)  
Маппинг в воркере: `worker/pipeline.py` → `_resolve_options`.

| Галочка UI (`methods`) | Runner | Что запускается |
|---|---|---|
| `sast` | `static` | Bandit + Semgrep (+ soft-skip) + pip-audit + context |
| `llm_agentic` | `ai` | triage / discovery / review (только если `ai` в methods) |
| `dast` | `dynamic` | sandbox Docker + preflight + ZAP baseline |
| `pentest` | `manual` | security review → sandbox verify → активный pentest-агент (`available: true`) |

В `ScanResult.meta.runners` должен быть **ровно** список выбранных runners. Секции HTML-отчёта строятся только по ним (`worker/rendering.py`: `static→sast`, `ai→llm`, `dynamic→dast`, `manual→pentest`).  
`summary.scan_kind` / подпись «Тип проверки» на странице заявки: из runners (`sast+pentest`, `sast+dast`, …) или напрямую из `options.methods` в UI.

### 3.2 Форматы → файлы

Источник: [`frontend/config/reports.yaml`](../frontend/config/reports.yaml)

| Документ | Имена файлов | Примечание |
|---|---|---|
| Отчёт аудита | `report.{html,md,pdf}` | form formats; docx — legacy |
| Документация ФСТЭК | `doc.{html,md,pdf}` | form formats; docx — legacy |
| LLM-протокол ФСТЭК | `fstec.{html,md,pdf}` | только если `ai_documents.enabled` |
| LLM codedocs | `codedocs.zip` | только если `ai_documents.enabled` |

План файлов: `Pipeline._format_plan(formats)` → сначала `report`/`doc`, затем `fstec`/`codedocs` если `ai_documents.enabled`.  
После core-артефактов воркер сразу пишет `manifest` с `report: ok` (UI разблокируется), LLM-доки дописываются и обновляют `manifest.artifacts` по одному документу.  
В `manifest.artifacts` — только эти имена. **Не** добавлять `dast_report.*`, `audit_report.md`, сырой SARIF.

**Очередь:** один worker = один скан. Основной отчёт больше не ждёт OpenRouter; AI-доки ограничены по промпту (~80k) и таймауту (~120 с), при ошибке — placeholder (включая `codedocs.zip`). Конфиг: `worker/config/worker.yaml` → `ai_documents`.

### 3.3 Job options (очередь)

`data/queue/{scan_id}.json` должен доезжать до воркера с полями:

```json
{
  "scan_id": "...",
  "source": { "kind": "link|zip|files", "...": "..." },
  "options": {
    "methods": ["sast", "llm_agentic", "dast"],
    "formats": ["html", "md", "pdf"]
  }
}
```

### 3.4 Гейтинг анализа

[`app/services/scan/orchestrator.py`](../app/services/scan/orchestrator.py):

- нет `static` → handlers.analyze не зовутся (для AI-only допускается context-only без SAST-tools);
- нет `ai` → **никаких** вызовов OpenRouter / triage / discovery / review;
- нет `dynamic` → `merge_dast_via_sandbox` не вызывается.

Legacy: `methods is None` → историческое поведение (SAST + опционально AI по флагу + DAST по умолчанию).

---

## 4. Конвейер анализа (внутри orchestrator)

Порядок: **static → ai → ranking → dynamic**.

### 4.1 Static (SAST)

- Вход: `PythonHandler.analyze` → `run_static_stage` → `app/sast/engine.py`.
- Инструменты по умолчанию: `config/settings.yaml` → `sast.tools.python: [bandit, semgrep]`; тяжёлые codeql/eslint в `config/sast.yaml` выключены.
- Soft-skip: нет бинаря / ошибка инструмента → запись в meta, скан продолжается.
- Windows: для Semgrep в `app/sast/tools.py` обязательны `PYTHONUTF8=1` / `PYTHONIOENCODING=utf-8` (иначе SARIF падает на emoji, `rc=2`).
- Артефакты: `data/reports/{scan}/` **или** `data/workspaces/{project}/reports/{analyzer_scan}/secaudit/{lang}/` — SARIF, merged.jsonl, context JSON. Не в UI.

### 4.2 AI (LLM)

Конфиг: `config/settings.yaml` → `ai` + env:

| Переменная | Назначение |
|---|---|
| `AI_API_KEY` | ключ (или `OPENROUTER_API_KEY` при base_url OpenRouter) |
| `AI_BASE_URL` | например `https://openrouter.ai/api/v1` |
| `AI_MODEL` | например `openrouter/free` |
| `AI_MODES` | опционально: `review,triage,discovery` |
| `WORKER_ENABLE_AI` | для legacy jobs без methods; при form-driven достаточно `ai` в methods |

Режимы:

1. **triage** — вердикты по SAST-находкам;
2. **discovery** — поиск от entrypoints/sinks;
3. **review** — обзор отобранных файлов (старый контур).

Findings: `source` ∈ `ai`, `ai-discovery`. FP от triage — `extra.dismissed` (в активной HTML-секции не показывать). Soft-fail сети/квоты.

### 4.3 Dynamic (DAST)

- Только при `dynamic` в methods.
- Sandbox: heuristic Dockerfile (`app/sandbox/`), для старых demo-deps: `six`, `markupsafe<2.1`, `itsdangerous<2.1`.
- Preflight + ZAP baseline (`config/settings.yaml` → `dast`, `sandbox`).
- Нужен **запущенный Docker Desktop**.
- Не поднялось → `meta.dast.status=skipped|failed`, SAST/LLM не откатываются.

### 4.4 Ranking

`app/services/scan/ranking.py`: конфигурации `S` / `S+T` / `S+D` / `S+T+D`. Пишется в `secaudit/ranking.json` и `meta.ranking`. Служебный `audit_report.md` может появиться в reports dir — **не** в manifest.

---

## 5. Отчёты (вид)

Рендер: `worker/rendering.py` + `worker/templates/report.html.j2`.

Требования к HTML-отчёту аудита:

- секции **только** по `meta.runners`;
- секции SAST / LLM / DAST — **сворачиваемые** (`<details>`), со счётчиком;
- длинные описания — превью + «Показать полностью»; HTML из ZAP очищать до текста;
- длинные строки — `overflow-wrap` / `word-break`, без вылезания за край;
- PDF: WeasyPrint (Linux) или xhtml2pdf (Windows); сбой одного формата **не** валит остальные (`worker/pipeline.py`).

Кнопки на странице скана = documents × formats из `reports.yaml`. Нужные пользователю по смыслу:

- **Отчёт аудита** — основной результат;
- **Документация ФСТЭК** — черновик комплекта;
- MD/PDF — те же документы для скачивания.

---

## 6. Окружение и запуск

### 6.1 Требования

- Python 3.11+ (проверено с 3.12/3.14 в venv проекта)
- git
- Docker Desktop (для DAST)
- сеть (pip-audit, GitHub clone, OpenRouter/LLM, ZAP image)

### 6.2 Установка

```bash
# из корня репозитория
py -3.12 -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\pip install -r frontend\web\requirements.lock
# опционально research:
.venv\Scripts\pip install -r requirements-bench.txt
```

### 6.3 `.env` (пример)

```env
AI_ENABLED=true
AI_API_KEY=...
AI_BASE_URL=https://openrouter.ai/api/v1
AI_MODEL=openrouter/free
```

### 6.4 Локальный запуск (два процесса)

**Терминал 1 — web:**

```bat
set SIRIUS_DATA_DIR=%cd%\data
.venv\Scripts\python -m uvicorn app.main:app --app-dir frontend\web --host 127.0.0.1 --port 8000
```

**Терминал 2 — worker:**

```bat
set WORKER_DATA_DIR=%cd%\data
set WORKER_ENABLE_AI=true
rem опционально долгие LLM-доки (по умолчанию выкл.):
rem set WORKER_ENABLE_AI_DOCUMENTS=true
.venv\Scripts\python -m worker
```

Открыть: http://127.0.0.1:8000/

### 6.5 Docker Compose

```bash
docker compose up --build
```

Сервисы `web` + `worker`, общий volume `./data`.

### 6.6 CLI (вне UI)

```bash
python -m app scan PATH|URL [--ai/--no-ai]
python -m bench --help          # research benchmark, не UI
```

---

## 7. Критерии приёмки (чеклист)

Сделать e2e и убедиться:

| Проверка | Ожидание |
|---|---|
| Только SAST + html | `meta.runners=["static"]`; секция только SAST; нет LLM/DAST секций |
| SAST+LLM | runners static+ai; секции SAST+LLM; без dynamic |
| SAST+DAST (Docker up) | sandbox ok или skip с meta; секция DAST есть |
| SAST+LLM+DAST + html,md,pdf | все три секции; артефакты report/doc × html,md,pdf в manifest |
| Только DAST | static skipped; нет SAST-сканеров |
| Без AI в methods | в логах нет `chat/completions` / OpenRouter |
| Semgrep на Windows | не обязан падать с `rc=2` UnicodeEncodeError (UTF-8 env) |
| PDF fail | html/md всё равно в manifest при выборе |
| UI | те же две группы галочек; нет новой кнопки «Отчёт DAST» |

Автотесты-контракт:

```bash
.venv\Scripts\python -m pytest tests/test_contract_methods_formats.py tests/test_secaudit_hooks.py worker/tests -q
# frontend (из frontend/web):
..\..\.venv\Scripts\python -m pytest tests -q
```

Референс полного прогона: репозиторий вроде `adzerk/purposefully-vulnerable-repo` (SAST+LLM+DAST, ~минуты на LLM/ZAP).

---

## 8. Карта кода (куда смотреть)

| Тема | Где |
|---|---|
| Форма / methods / formats | `frontend/config/analysis.yaml`, `reports.yaml`, `forms/audit_form.yaml` |
| Intake → queue | `frontend/web/app/services/intake.py`, `registry.py` |
| Воркер / plan артефактов | `worker/pipeline.py`, `worker/formats.py` |
| Оркестратор | `app/services/scan/orchestrator.py` |
| SAST | `app/sast/**`, `app/languages/sast_support.py`, `config/sast.yaml` |
| Context | `app/context/**`, `config/sinks.yaml` |
| LLM | `app/ai/pipeline.py`, `triage.py`, `discovery.py`, `llm.py`, `config.py` |
| Ranking / audit md | `app/services/scan/ranking.py`, `app/services/report/audit.py` |
| DAST / sandbox | `app/services/scan/dast_merge.py`, `app/sandbox/**` |
| HTML-отчёт | `worker/templates/report.html.j2`, `worker/rendering.py` |
| Смысл для пользователя | `docs/process.md` |
| Research / bench | `bench/`, `docs/BENCHMARK.md`, `docs/REPORT.md` |

---

## 9. Запреты при доработках

1. Не мержить оркестратор/шаблоны из PR secaudit **целиком** — только пакеты внутрь наших runners.
2. Не расширять `reports.yaml` новыми document id без продуктового решения.
3. Не запускать LLM, если в job нет `ai`.
4. Не запускать DAST, если нет `dynamic`.
5. Не класть SARIF / `secaudit/` / `audit_report.md` в `manifest.artifacts`.
6. Не ломать DAST-хуки Python (`detect_runnable`, `analyze_dast`) при правке `analyze()`.

---

## 10. Известные особенности

- Semgrep без UTF-8 на Windows → пустой SARIF / `rc=2` (исправлено через env в `tool_env`).
- OpenRouter free: transient connection errors; ретраи укорочены, soft-fail.
- Старые Flask-demo в sandbox: нужны compat-пины в `dockerfile_gen.py`.
- WeasyPrint на Windows без GTK не работает — fallback xhtml2pdf; огромные отчёты могут потребовать упрощённого HTML для PDF.
- `bench/` не нужен для продуктового UI; датасет собирается отдельно (`python -m bench bench build`).

---

## 11. Минимальный handoff «с нуля»

1. Клонировать репо, checkout `feature/secaudit-integrate` (или актуальный master после merge).
2. Создать venv, поставить `requirements.txt` + `frontend/web/requirements.lock`.
3. Прописать `.env` с AI-ключом (если нужен LLM).
4. Запустить Docker Desktop (если нужен DAST).
5. Поднять web + worker с **одним** `data/`.
6. Пройти чеклист §7 на маленьком/уязвимом репо.
7. Прочитать `docs/process.md` перед изменением UX.

Если после правок «пропала» секция метода или появились лишние кнопки отчёта — сначала проверить §3 (контракт), а не движок SAST.
