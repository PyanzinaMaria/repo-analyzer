# Аудитор репозиториев

Монорепозиторий системы аудита кода: **продуктовый сервис с веб-интерфейсом** и
**исследовательский CLI/lab-контур** рядом с ним. Связь web ↔ worker — только через
общее дерево `data/` (без HTTP между сервисами).

| Контур | Как пользоваться | Куда смотреть |
|---|---|---|
| **Продукт** | Форма в браузере → галочки методов → единый отчёт | этот README § «Продукт», [`docs/process.md`](docs/process.md) |
| **Research** | CLI / lab-скрипты, без формы скана | § «Исследовательская часть», [`docs/REPORT.md`](docs/REPORT.md), [`docs/LIVE_SEQUENCE_RUNNER.md`](docs/LIVE_SEQUENCE_RUNNER.md), [`docs/llmflow/`](docs/llmflow/README.md) |

---

## Продукт: запуск через интерфейс

Принимает репозиторий (GitHub/GitLab или zip/файлы), по галочкам гоняет выбранные
методы и отдаёт **единый отчёт аудита** + **документацию ФСТЭК** в выбранных форматах.

```
Браузер ──HTTP──▶ WEB :8000 ──▶ data/uploads/{id}/ + data/queue/{id}.json
                                      │
WORKER ──поллинг queue/──▶ claim → IngestService → ScanOrchestrator (app/)
   ▼
data/reports/{id}/  ◀── report.* · doc.* · manifest.json · summary.json
                                      │
Браузер ◀── HTMX /scan/{id} ── WEB читает reports/
```

| Компонент | Путь | Роль |
|---|---|---|
| Web | `frontend/web` | Форма, intake, статус, раздача артефактов |
| Worker | `worker/` | Очередь, анализ, рендер отчётов |
| Analyzer | `app/` | Библиотека раннеров (SAST / LLM / DAST / пентест) |

Подробный смысл для пользователя: [`docs/process.md`](docs/process.md).  
Инженерный handoff (контракты, что нельзя ломать): [`docs/SPEC.md`](docs/SPEC.md).

### Методы в форме

Источник выбора — [`frontend/config/analysis.yaml`](frontend/config/analysis.yaml):

| Галочка | Runner | Что делает |
|---|---|---|
| **SAST** | `static` | Bandit + Semgrep + pip-audit + контекст кода |
| **LLM-агент** | `ai` | Triage / discovery / review поверх статики |
| **DAST** | `dynamic` | Песочница Docker + preflight + ZAP |
| **Пентест** | `manual` | Гипотезы по коду → проверка на живом приложении → активный агент |

По умолчанию включён только SAST. Методы можно комбинировать. Неотмеченный метод
просто пропускается. Служебные артефакты (`secaudit/`, SARIF и т.п.) на страницу
скана кнопками не выводятся.

Форматы отчёта — [`frontend/config/reports.yaml`](frontend/config/reports.yaml)
(`report.*`, `doc.*`; опционально LLM-доки `fstec.*` / `codedocs.zip` по
`worker/config/worker.yaml` → `ai_documents`).

Пентест-агент (схема и доки): [`docs/PENTEST_AGENT_OVERVIEW.md`](docs/PENTEST_AGENT_OVERVIEW.md) ·
[`docs/SECURITY_PIPELINE.md`](docs/SECURITY_PIPELINE.md) ·
[`docs/LLM_PROVIDERS.md`](docs/LLM_PROVIDERS.md).

### Быстрый старт продукта

**Docker** (web :8000 + worker, общий `./data`):

```bash
docker compose up --build
```

**Локально** (два процесса, Python 3.11+, git):

```bash
# Windows; один venv на всё
py -3.12 -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\pip install -r frontend\web\requirements.lock

# 1) веб
set SIRIUS_DATA_DIR=%cd%\data
.venv\Scripts\python -m uvicorn app.main:app --app-dir frontend\web --port 8000

# 2) воркер (второй терминал, из корня)
.venv\Scripts\python -m worker
```

Открыть http://127.0.0.1:8000/ — подать репозиторий, выбрать методы и форматы.
`SIRIUS_DATA_DIR` и `WORKER_DATA_DIR` должны указывать на **один** абсолютный путь,
иначе заявка «зависнет» после intake.

Linux/macOS: `python3 -m venv .venv`, `export SIRIUS_DATA_DIR=$PWD/data`, пути через `/`.

Env воркера: `WORKER_DATA_DIR`, `WORKER_POLL_INTERVAL_SECONDS`, `WORKER_ENABLE_AI`
(+ `AI_API_KEY` для LLM-метода). ИИ-модель клиенту не выбирается — берётся из
`config/settings.yaml` / `AI_MODEL`.

### Файловый контракт (кратко)

| Дерево | Кто пишет | Кто читает |
|---|---|---|
| `data/queue/{scan_id}.json` | web | worker (claim → `.claimed`) |
| `data/uploads/{scan_id}/repo/` | web | worker |
| `data/reports/{scan_id}/manifest.json` | worker | web (статус) |
| `data/reports/{scan_id}/summary.json` | worker | web (donut) |
| `data/reports/{scan_id}/{document}.{format}` | worker | web (просмотр / скачивание) |

Полная таблица и чеклист приёмки — в [`docs/SPEC.md`](docs/SPEC.md).

---

## Исследовательская часть

Всё ниже **не** является методом формы скана и **не** подменяет UI-отчёт.
Нужно для экспериментов, бенчмарков и CLI-отладки анализатора.

| Инструмент | Запуск | Зачем |
|---|---|---|
| **secaudit / bench** | `python -m app`, `python -m bench` | Research-контур аудита и оценка на CVE-бенчмарке (165 items) |
| **llmflow** | `python -m app llmflow …` | Потоки «недоверенный ввод → промпт → LLM → опасный сток», ранжирование S·E·R |
| **Live sequence runner** | `live_test_runner/` | Lab HTTP-обход живого приложения: GA / Q-learning / покрытие UI |
| **Offline sequence benchmarks** | `offline_sequence_benchmarks/` | Офлайн-бенчмарки тех же алгоритмов на синтетическом графе / HTML |
| **Sandbox / стенды** | `sandbox/` | Учебные и уязвимые цели для DAST/пентеста |

Документация research:

- [`docs/REPORT.md`](docs/REPORT.md) — как устроен secaudit-контур и что он находит
- [`docs/BENCHMARK.md`](docs/BENCHMARK.md) — статистика CVE-бенчмарка
- [`docs/llmflow/`](docs/llmflow/README.md) — модуль LLM-потоков (каталог SDK, stitching, примеры, бенч на TaintP2X)
- [`docs/LIVE_SEQUENCE_RUNNER.md`](docs/LIVE_SEQUENCE_RUNNER.md) — live HTTP + GA/Q-learning
- [`offline_sequence_benchmarks/`](offline_sequence_benchmarks/) — офлайн-варианты тех же идей

Пример llmflow (когда модуль в дереве):

```powershell
python -m app llmflow test-rules
python -m app llmflow scan path\to\repo --svg report.svg --mermaid graphs.md
```

Артефакты llmflow пишутся в `data/llmflow/` (в `.gitignore`).

---

## Анализатор как библиотека / API

Воркер вызывает `app/` напрямую. Отдельный HTTP-сервис нужен для отладки:

```bash
uvicorn app.main:app --port 8001
```

Swagger: `/docs`. Скан: `POST /api/v1/projects` → `POST …/scans` с
`{"methods": ["static", "ai", …]}` (ключи раннеров, см. `app/analysis/registry.py`).

Языки: [`config/settings.yaml`](config/settings.yaml) → `enabled_languages`
(сейчас полноценно — Python). Контракт плагина: `app/languages/base.py`.

> Черновик ФСТЭК **не** является сертифицированным комплектом по приказу №76.

---

## Структура репозитория

```text
frontend/         # веб-UI (форма, статус, артефакты)
  config/         # analysis.yaml, reports.yaml — контракт галочек
worker/           # очередь → анализ → отчёты
app/              # анализатор: SAST / AI / DAST / security / llmflow
config/           # settings.yaml анализатора
bench/            # research CLI и CVE-бенчмарк
live_test_runner/ # lab HTTP-обход
offline_sequence_benchmarks/
sandbox/          # цели для динамических проверок
docs/             # process, SPEC, research-доки
data/             # runtime queue/uploads/reports (gitignored)
```

---

## Тесты

```bash
.venv/Scripts/python -m pytest worker/tests -q
cd frontend/web && ../../.venv/Scripts/python -m pytest
pytest -q                                          # анализатор (pip-audit — сеть)
```

---

## Документация

| Документ | Для кого |
|---|---|
| [`docs/process.md`](docs/process.md) | Пользователь / продукт: галочки, порядок анализа, что в отчёте |
| [`docs/SPEC.md`](docs/SPEC.md) | Инженер: контракты, запуск, приёмка |
| [`frontend/README.md`](frontend/README.md) | Детали фронтенда |
| [`docs/REPORT.md`](docs/REPORT.md) / [`docs/BENCHMARK.md`](docs/BENCHMARK.md) | Research secaudit / bench |
| [`docs/llmflow/`](docs/llmflow/README.md) | Research llmflow |
| [`docs/LIVE_SEQUENCE_RUNNER.md`](docs/LIVE_SEQUENCE_RUNNER.md) | Research live HTTP runner |
| [`docs/PENTEST_AGENT_OVERVIEW.md`](docs/PENTEST_AGENT_OVERVIEW.md) | Пентест в продуктовом контуре |
