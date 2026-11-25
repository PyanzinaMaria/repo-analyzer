# Совместимость с repo-analyzer (ветка `feature/security-pentest-agent`)

Ветка создана от `origin/master` (`2ed8522`, 25.11.2026) — то есть уже **после**
интеграции `secaudit` в master (SAST + контекст + LLM-триаж + CLI). Поэтому
`app/context`, `app/sast`, `app/ai`, `app/cli.py` берутся из master как есть,
а ветка добавляет только новый слой.

## Что добавлено

| Путь | Назначение |
|---|---|
| `app/security/*` | единый security pipeline: гипотезы → плагины × стратегии → проверка → judge → отчёты |
| `app/dast/agent/*` | активный pentest-агент (crawl, probes, LLM-планировщик, MCP-сервер, CLI) |
| `config/security.yaml` | конфиг-как-код: провайдер LLM, режим ревью, плагины, стратегии, бюджеты, auth |
| `docs/PENTEST_AGENT_OVERVIEW.md` + `docs/images/*` | объяснение и схема |
| `docs/PENTEST_AGENT.md`, `docs/PENTEST_AGENT_RUN.md` | устройство агента и инструкция по запуску |
| `docs/SECURITY_PIPELINE.md` | гипотезы, верификация, judge, SARIF |
| `docs/LLM_PROVIDERS.md` | Groq / GigaChat / OpenRouter / Gemini / Ollama, ключи и лимиты |
| `docs/RUN_SCENARIOS_PVR.md` | проверка на реальном уязвимом репозитории |
| `tests/test_security_pipeline.py`, `tests/test_llm_providers.py`, `tests/test_pentest_agent.py` | тесты |
| `tests/fixtures/vuln_web_app.py`, `tests/fixtures/repo_demo/` | стенды для тестов |

## Интеграционные точки (изменены минимально)

1. `app/services/scan/orchestrator.py`
   - после SAST + LLM-стадии запускается `run_security_scan(root, None, findings=..., use_llm=run_ai)`;
   - новые findings (`source=llm-review|review-agent`) добавляются в общий список;
   - гипотезы сохраняются в `meta.security_hypotheses`, счётчики — в `meta.security`
     и `summary.security_hypotheses/review_findings`;
   - review не запускается для чисто динамических сканов (`methods=["dynamic"]`).

2. `app/services/scan/dast_merge.py`
   - после поднятия песочницы вызывается `verify_only(...)` для гипотез
     (сначала `host_url`, при неудаче — `network_url`);
   - подтверждённые находки (`source=pentest`) добавляются в результат,
     мета — в `meta.security_verify`, счётчики — в `summary.pentest_findings`.

3. `app/dast/orchestrator.py`, `app/dast/config.py`, `app/dast/zap_baseline.py`
   - активный pentest-агент запускается после пассивного ZAP baseline;
   - добавлены `dast.zap_enabled` и `dast.pentest.*` (при этом сохранены
     upstream-настройки `work_dir`/`docker_volume` для контейнерного воркера).

4. `config/settings.yaml`
   - добавлена секция `dast.pentest` и `dast.zap_enabled` (значения по умолчанию
     не меняют поведение master, кроме появления активного этапа).

## Ветки master, которые стоит знать

- `origin/master` — актуальная интеграция: SAST + контекст + LLM-триаж/review +
  DAST-песочница + отчёты; в нём уже есть `app/context` и `app/sast`.
- `origin/secaudit` — исследовательская линия (бенчмарк, discovery/triage);
  в master вошла частично.
- `origin/feature/live-sequence-runner` (m11yrr) — live HTTP-раннер с GA и
  Q-learning: это будущий источник RL-гипотез. В нашем пайплайне для него уже
  есть `Source.rl` и адаптер `VulnHypothesis`.
- `origin/input-test-gen` (ankmlva) — генерация DAST-тестов (RL + GA) на
  синтетических HTML-фикстурах.
- `origin/codex/fstec-company-report` — настраиваемый отчёт для компании.

## Тесты

`pytest tests worker/tests` на этой ветке: **119 passed, 1 skipped, 2 failed**.
Оба падения **воспроизводятся на чистом `origin/master`** (проверено в отдельном
worktree) и не связаны с агентом:

- `tests/test_ai_analysis.py::test_scan_endpoint_accepts_enable_ai_body` —
  ожидает `test_stub`, получает `missing_api_key` (приоритет ошибок в
  `ai_meta` не учитывает stub `run_ai_analysis`);
- `worker/tests/test_dast_pipeline.py::test_dast_result_folds_into_unified_report` —
  тест манифеста PDF-артефактов зависит от наличия PDF-движка: без него нет
  `doc.pdf`, с `xhtml2pdf` появляется лишний `report.pdf`.

Наши тесты (`test_security_pipeline`, `test_llm_providers`, `test_pentest_agent`)
проходят полностью.

## Что не сделано намеренно

- Не менялись другие ветки и `master`.
- Не дублировались `app/context`/`app/sast` — используются версии master
  (файлы побайтово совпадают с тем, что мы портировали ранее).
- UI-страница для гипотез/подтверждений не добавлялась: отчёты и мета уже
  попадают в `security_report.json`, `meta.security*`; отображение — задача
  интеграции в master, которую делает отдельный человек.
