# Security pipeline: ревью кода → гипотезы → пин-тест → judge → отчёт

Единый контур, который объединяет лучшее из нашего проекта (SAST, tree-sitter
контекст, DAST, песочница, отчёты ФСТЭК) и из **promptfoo Code Scanning**
(агентное исследование кода, «guidance», порог severity, SARIF, идея
plugin × strategy из red teaming).

Схема: [`images/pentest-agent-flow.png`](images/pentest-agent-flow.png) ·
краткое описание: [PENTEST_AGENT_OVERVIEW.md](PENTEST_AGENT_OVERVIEW.md).

Ищет **не только LLM-уязвимости**, а общие классы: SQLi, XSS, path traversal,
SSRF, XXE, инъекции команд, open redirect, небезопасную десериализацию,
секреты в коде, security-заголовки, раскрытие ошибок, prompt injection.

```
            ┌────────────────────────── REVIEW ──────────────────────────┐
 репозиторий│  context (tree-sitter, callgraph, entrypoints, sinks)      │
            │        │                                                   │
            │        ├── agentic LLM review (tools: read/grep/outline/…) │
            │        └── deterministic review (fallback без LLM)         │
            └───────────────────────────┬────────────────────────────────┘
                                        ▼
                        VulnHypothesis (class, cwe, file:line,
                        endpoint, param, confidence, source: sast|llm|rl|crawl)
                                        │  приоритизация (risk scoring)
                                        ▼
            ┌────────────────────────── VERIFY ──────────────────────────┐
            │  plugins (класс уязвимости) × strategies (кодирование)     │
            │  HTTP-проверки по конкретному endpoint+param               │
            │  detectors (сигнатуры/маркеры)                             │
            │  LLM-as-judge (FP-фильтр; без LLM — rules-вердикт)         │
            └───────────────────────────┬────────────────────────────────┘
                                        ▼
              Verdict: confirmed / refuted / uncertain / skipped
                                        │
                                        ▼
        Finding(source=pentest|llm-review|review-agent) + Markdown/JSON/SARIF
```

---

## 1. Из чего собрано (что и откуда взято)

| Идея | Источник | Реализация |
|---|---|---|
| Плагины (что искать) | promptfoo red teaming | `app/security/plugins.py` — 11 плагинов на общие CWE |
| Стратегии (как доставлять) | promptfoo red teaming | `app/security/strategies.py` — raw, urlencode, double, case, sql_comment, space_tab |
| Агентное сканирование кода инструментами | promptfoo Code Scanning | `app/security/code_review.py` — LLM получает `list_files/read_file/grep/outline/entrypoints/sinks/callgraph` и сам исследует репозиторий |
| Guidance / политика заказчика | promptfoo Code Scanning | `review_guidance` в `config/security.yaml` |
| Порог severity, SARIF | promptfoo Code Scanning | `min_severity`, `report.to_sarif()` |
| LLM-as-judge | promptfoo evaluation | `app/security/judge.py` |
| Конфиг-как-код | promptfoo | `config/security.yaml` |
| Гипотезы + риск-скоринг | наше (новое) | `app/security/models.py`, `risk.py` |
| Код-контекст (entrypoints/sinks/callgraph) | наш исследовательский слой (`secaudit`) | `app/context/*` (портирован) |
| DAST-песочница и отчёты | наш проект | `app/sandbox/*`, `app/dast/*`, `app/services/report/*` |

---

## 2. Как рождаются гипотезы

### 2.1 Из SAST

`app/security/sast_adapter.py`: `Finding` → `VulnHypothesis` по CWE/правилу,
с уверенностью в зависимости от инструмента (codeql 0.85, semgrep 0.75,
bandit 0.7, AI 0.55).

### 2.2 Из ревью кода (детерминированное, без LLM)

`deterministic_hypotheses()`:

1. Берёт каждый опасный вызов из `sinks.yaml` (`cursor.execute`, `os.system`,
   `pickle.loads`, …).
2. Определяет, является ли функция точкой входа; если нет — ищет **предков по
   графу вызовов** (до 4 шагов) и берёт маршрут ближайшей точки входа.
3. Извлекает `endpoint`, HTTP-метод и параметры: декораторы Flask/FastAPI,
   `request.args.get("q")`, `request.form[...]`, `req.query.x`; префиксы
   blueprint/router резолвятся (`url_prefix='/user'` + `@mod_user.route('/login')`
   → `/user/login`).
4. Добавляет паттерны: секреты в коде, `eval/exec`, `pickle`, `yaml.load`,
   `render_template_string`, `innerHTML`, `shell=True` и т.п.

Это даёт гипотезы даже без LLM и без ключа — и именно они «надавливаются»
динамически.

### 2.3 Из ревью кода (LLM-агент)

`llm_hypotheses()`:

- модели даётся бриф: размер репозитория, точки входа с маршрутами, топ стоков
  по CWE, требования заказчика (`review_guidance`);
- дальше — цикл tool-calling: `grep` → `read_file` → `outline` → `callgraph` →
  `submit` (JSON-схема гипотез);
- ответ валидируется: файл обязан существовать в индексе, класс — из
  перечисления, confidence/severity нормализуются, evidence вырезается из кода;
- при ошибке/лимите LLM — автоматический fallback на детерминированное ревью;
- результат кэшируется (SQLite, `data/llm_cache/security.sqlite`), чтобы
  повторные сканы не тратили бесплатную квоту.

### 2.4 Из живой поверхности (crawl fallback)

Если маршрут из кода не выводится (фикстуры, Go/Java-хендлеры, динамические
роуты), `crawl_hypotheses()` обходит приложение, берёт формы/query-параметры и
сопоставляет их с подсказками плагинов (`next` → redirect, `path` → traversal,
`cmd` → command injection, …).

### 2.5 Из RL (задел на будущее)

`Source.rl` уже есть в модели. Достаточно адаптера
`RL finding → VulnHypothesis` (class, file:line, endpoint, confidence) и
добавления в общую очередь — остальной конвейер не меняется.

---

## 3. Верификация: плагины × стратегии

Каждая гипотеза превращается в набор `ProbePlan`:

- **plugin** выбирается по классу уязвимости (`sqli`, `xss`, `path_traversal`,
  `open_redirect`, `cmd_injection`, `xxe`, `ssrf`, `insecure_deserialization`,
  `prompt_injection`, `missing_headers`, `error_disclosure`);
- **payload** — канонический набор плагина;
- **strategy** — преобразование (urlencode/double/case/sql_comment/space_tab);
- **endpoint/param** — из гипотезы (или crawl-фолбэка);
- **детектор** — сигнатуры: ошибка БД, отражение в HTML, `root:x:0:0`,
  `Location: evil.example`, маркер команды **без** отражения payload, XML-сущность,
  отсутствие заголовков, traceback, маркер prompt injection **без** отражения.

Бюджеты: `verify_max_hypotheses=20`, `verify_max_requests=200`,
`verify_max_seconds=120`, задержка 150 мс, только same-origin, SSRF-политика.

Для XSS/prompt-injection стратегии кодирования отключены — процентно
закодированный `<script>` в теле не является уязвимостью (иначе получаем ложные
срабатывания).

---

## 4. LLM-as-judge (фильтр ложных срабатываний)

Когда детектор сработал, судья (бесплатная модель) получает гипотезу, payload и
фрагмент ответа и выносит `confirmed | refuted | uncertain` + severity +
объяснение. Правила слияния:

- судья может **опровергнуть** подтверждённое детектором (FP-фильтр);
- судья **не может подтвердить** то, чего детектор не увидел;
- без LLM остаётся rules-вердикт (порог 0.6), поэтому конвейер работает всегда.

---

## 5. Что попадает в отчёт

`data/security/security_review.md` — человекочитаемо:
топ рисков (P0–P3), подтверждённые находки с payload/запросом/ответом,
гипотезы без подтверждения (файл:строка, риск, причина).

`data/security/security_review.json` — всё: `meta`, гипотезы, вердикты, findings.

`data/security/security_review.sarif` — SARIF 2.1.0 для CI/IDE.

В общем отчёте проекта (`security_report.*`, `fstec_draft.md`) находки выглядят
как обычные `Finding` с `source`:
- `pentest` — подтверждено динамически;
- `llm-review` / `review-agent` — найдено ревью кода.

---

## 6. Запуск

```powershell
# 1) только ревью кода (гипотезы + review-находки), без цели
.\.venv\Scripts\python -m app.security review --repo C:\path\to\repo --no-llm --out data\security\review

# 2) ревью + динамическая проверка
.\.venv\Scripts\python -m app.security scan --repo C:\path\to\repo `
    --url http://127.0.0.1:5000 --no-llm --allow-private --out data\security\run

# 3) проверить готовые гипотезы
.\.venv\Scripts\python -m app.security verify --repo . --url http://host:port `
    --hypotheses data\security\review\security_review.json --allow-private

# 4) с LLM (нужен бесплатный ключ)
$env:OPENROUTER_API_KEY="sk-or-..."
.\.venv\Scripts\python -m app.security scan --repo C:\path\to\repo --url http://host:port
```

Тестовый стенд: `python tests\fixtures\vuln_web_app.py --port 5001`.

---

## 7. Конфиг (`config/security.yaml`)

| Ключ | Смысл |
|---|---|
| `review_enabled` | включить ревью кода |
| `review_max_repo_files` | предохранитель для очень больших репозиториев (2500) |
| `review_max_hypotheses` | сколько гипотез оставить (25) |
| `review_guidance` | свободные требования к ревьюеру (аналог promptfoo guidance) |
| `from_sast` | конвертировать SAST-находки в гипотезы |
| `verify_max_hypotheses/requests/seconds` | бюджеты динамики |
| `verify_allow_private` | разрешить localhost/RFC1918 |
| `crawl_fallback` | гипотезы по живой поверхности, когда код не даёт маршрут |
| `plugins` / `strategies` | что и как проверять |
| `llm_model` / `llm_base_url` / `llm_timeout` | бесплатная модель (провайдер: Groq / GigaChat / OpenRouter / Gemini / Ollama; см. `LLM_PROVIDERS.md`) |
| `llm_provider` | провайдер; пусто = автоопределение по base_url |
| `llm_max_retries` / `llm_json_mode` | повторы при битом JSON и JSON-режим |
| `llm_verify_ssl` | проверка TLS (для GigaChat без сертификатов Минцифры — `false`) |
| `judge_enabled` | LLM-судья |
| `min_severity` | порог попадания в отчёт |
| `cache_path` | кэш LLM-ответов |

---

## 8. Интеграция в продукт

- `app/services/scan/orchestrator.py`: после SAST и AI-ревью запускается
  security review; находки добавляются в результат, гипотезы сохраняются в
  `meta.security_hypotheses`, счётчики — в `meta.security`.
- `app/services/scan/dast_merge.py`: после поднятия песочницы гипотезы
  проверяются на живом приложении (`verify_only`), сначала по `host_url`, при
  неудаче — по `network_url`; вердикты и находки попадают в общий результат
  (`meta.security_verify`).
- Заодно исправлена мёртвая ветка: раньше `_run` возвращал SAST-результат до
  вызова `merge_dast_via_sandbox`, поэтому DAST в продукте фактически не
  запускался.

---

## 9. Проверка (фактические прогоны)

| Сценарий | Результат |
|---|---|
| `pytest tests worker/tests` | **78 passed, 2 skipped** (включая 8 тестов security-pipeline) |
| Фикстура `tests/fixtures/vuln_web_app.py` | **8/8 подтверждено**: SQLi, 2×XSS, path traversal, command injection, open redirect, security-заголовки, раскрытие стека; 28 проверок / 52 запроса |
| `vulpy` (реальный репозиторий, 18 файлов) | **2 подтверждено** (SQLi на `/user/login` через цепочку `do_login → libuser.get_user → execute`, security-заголовки) + **11 review-находок** по коду; 42 проверки / 66 запросов |
| LLM-режим | реализован и покрыт тестом с мок-моделью; живой прогон требует `OPENROUTER_API_KEY` (в текущей среде ключ не задан) |

Ложные срабатывания, которые поймали и устранили по ходу:
отражение payload в ошибке (command injection), процентно-кодированный
`<script>` (XSS), отражённый маркер prompt injection, «чужие» стоки без
достижимости из точки входа, дубли одной уязвимости из разных мест кода.

---

## 10. Ограничения и следующий шаг

- **Аутентификация**: проверки идут без логина; для закрытых зон нужен сценарий
  входа (cookie/token) — добавить в `TargetClient`/`Verifier`.
- **SPA/JS**: браузерного таргета пока нет (только HTTP) — это следующий
  кандидат (Selenium/Puppeteer), как у promptfoo.
- **Diff-only режим** (сканировать только изменённые файлы/PR) — не реализован.
- **CI-гейт** по `min_severity`/SARIF — SARIF уже есть, гейт в пайплайне — далее.
- **RL-гипотезы** — модель готова (`Source.rl`), нужен адаптер от RL-агента.
- **Бенчмарк**: нужен набор уязвимых приложений с ground truth (Juice Shop,
  OWASP Benchmark, vulpy) и метрики precision/recall по классам.
