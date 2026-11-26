# Совместимость: ветка `feature/pentest-agent-ui`

Интеграционная ветка: merge `feature/security-pentest-agent` в актуальный
`master` + UI-связка галочки **«Пентест»** и стабилизация отчётов/AI-доков.

База: `origin/master` (после secaudit + ui-design). Слой агента не дублирует
`app/context` / `app/sast` / `app/ai` — берёт их из master.

## Состав

| Путь | Назначение |
|---|---|
| `app/security/*` | security pipeline: гипотезы → плагины × стратегии → verify → judge |
| `app/dast/agent/*` | активный pentest-агент (crawl, probes, LLM planner, MCP, CLI) |
| `config/security.yaml` | LLM, плагины, стратегии, бюджеты |
| `frontend/config/analysis.yaml` | `pentest` → runner `manual`, `available: true` |
| `docs/*` | overview, run, pipeline, providers, process/SPEC (UI) |
| `tests/test_security_pipeline.py`, `test_pentest_agent.py`, … | тесты агента и гейтинга UI |

## Как включается из UI

1. Форма: `methods` включает `pentest` → воркер мапит в runner **`manual`**.
2. `ScanOrchestrator`: security review только при `manual` (form jobs); legacy
   `methods=None` по-прежнему может идти по `config/security.yaml`.
3. Песочница: при `manual` и/или `dynamic`. ZAP — только если выбран DAST;
   активный агент — если выбран Пентест (или legacy + `dast.pentest.enabled`).
4. Отчёт: секция **«Пентест»**; `scan_kind` вида `sast+pentest` (не `sast+dast`).
5. Страница заявки показывает тип проверки по `options.methods`.

## Отчёты и AI-документы

- Core `report`/`doc` публикуются первыми → `manifest.stages.report=ok`.
- Затем `fstec` / `codedocs.zip`; манифест обновляется после каждого документа.
- Промпт LLM-доков ограничен (`select_files` + top findings, ≤ ~80k chars,
  timeout ~120 s) — см. `worker/ai_docs.py`, `worker/config/worker.yaml`.
- Ошибка LLM → placeholder, `codedocs.zip` всё равно появляется.

## Связанные ветки

- `origin/master` — SAST + контекст + LLM-триаж + DAST + UI.
- `origin/feature/security-pentest-agent` — исходный слой агента без UI-гейта.
- `origin/feature/live-sequence-runner` — будущий источник `Source.rl`.

## Что сознательно не делали

- Отдельный «дашборд гипотез» в UI: findings уже в секции Пентест / meta.
- Смена провайдера LLM по умолчанию (остаётся конфиг / env пользователя).
