# Live sequence runner — поиск тестовых последовательностей

Лабораторный контур **рядом** с продуктовым аудитом (SAST/DAST/ZAP). Не является методом в UI и не подменяет runner `dynamic`.

## Что это

Автоматический обход уже запущенного веб-приложения по HTTP:

1. из HTML извлекаются действия пользователя (ссылки, формы);
2. по мере выполнения строится **граф взаимодействий** (состояние → действие → новое состояние);
3. на графе работают **Q-learning** и **генетический алгоритм** (плюс Random и гибрид Q+GA);
4. на каждом ответе считаются признаки проблем качества;
5. в отчёт пишутся покрытие и **дедуплицированный** список находок.

Алгоритмы поиска последовательностей пришли из пакета [`offline_sequence_benchmarks/`](../offline_sequence_benchmarks/) (офлайн-бенчмарки на синтетическом графе и HTML-буклете в памяти). Пакет [`live_test_runner/`](../live_test_runner/) исполняет те же идеи уже по живому HTTP.

## Для чего

- Исследовать, насколько хорошо GA / Q-learning находят редкие или длинные цепочки UI-действий.
- Собирать **функциональное покрытие** интерфейса (страницы, состояния, переходы).
- Получать простую метрику качества ответа приложения: headers, cookie, отражение ввода, HTTP 4xx/5xx.

Это **не** полноценный сканер уязвимостей и **не** замена Bandit/ZAP. Находки — симптомы качества/конфигурации, а не подтверждённые CVE.

## Как работает

```text
Цель (HTTP)          Runner
    │                   │
    │◀── GET/POST ──────┤  парсинг ссылок и форм
    │── HTML ──────────▶│  state = hash стабилизированного HTML
    │                   │  ребро source → action → target
    │                   ├─ Random / Q-learning / Genetic / Q+GA
    │                   └─ detectors → findings → metrics.json
```

| Компонент | Роль |
|---|---|
| `live_test_runner/target/app.py` | Учебный HTTP-стенд «буклет» (навигация + формы, слабые headers) |
| `actions.py` | Извлечение действий; пустой `action` у формы = текущая страница |
| `graph_trial.py` | Живой граф, бюджет шагов, эпизоды с reset на start URL |
| `search.py` | Политики Random, Q-learning, Genetic, Q+GA (гиперпараметры из `hyperparams.json`) |
| `optuna_tune.py` | Подбор гиперпараметров Q/GA через Optuna (цель — обогнать Random) |
| `detectors.py` | Сырые счётчики + дедуп `kind\|detail` → `findings` |
| `pipeline.py` | Оркестрация методов и запись `metrics.json` |

Состояние — хеш HTML (с вырезанием CSRF-токенов), чтобы одна и та же страница не плодила узлы из‑за сессионного шума. Между эпизодами сессия сбрасывается, открывается `--start-path` (у буклета это эквивалент бесплатного возврата в начало).

## Метрики

Главное для человека:

| Поле | Смысл |
|---|---|
| **`problems_unique`** | Сколько **разных** динамических проблем (ключ `kind\|detail`) |
| **`findings[]`** | Список динамических находок: fingerprint, pages, occurrences |
| **`code_vulnerabilities`** | Сколько уязвимостей нашёл **Bandit** в исходниках цели (`--source-dir`) |
| `code_vulnerabilities_report` | Детализация SAST: severity, test_id, файл/строка |
| `states` / `transitions` | Насколько далеко залезли в UI |
| `problems_total` | Сырые срабатывания HTTP-детекторов (частота, не «число багов») |

Типы в `findings`:

- `missing_security_headers` — нет CSP / X-Frame-Options / и т.п.
- `insecure_cookies` — нет HttpOnly / Secure / SameSite
- `reflected_input` — отправленное значение видно в HTML
- `http_4xx` / `http_5xx` — ошибочные ответы

Пример smoke по буклету: `problems_unique = 13` при `problems_total = 1810` (повторы headers/cookie на каждом шаге + отражения на `/echo`, `/text`, `/palette`).

## Запуск

### Буклет в Docker (рекомендуемый smoke)

```bash
docker compose -f live_test_runner/docker-compose.yml up --build
```

Сервисы `webapp` (:8080) и `runner`. Результат: `live_test_runner/output/smoke/metrics.json`.

### Произвольная уже запущенная цель

```bash
pip install -r live_test_runner/requirements.txt
python -m live_test_runner \
  --profile smoke \
  --base-url http://127.0.0.1:5000 \
  --start-path /login \
  --output-dir live_test_runner/output/my-target
```

Профили: `smoke` (короткий бюджет) и `full`. Переменные: `TARGET_URL`, `TARGET_START_PATH`, `RUNNER_PROFILE`.

### Только офлайн-алгоритмы (без HTTP)

```bash
python -m unittest discover -s offline_sequence_benchmarks/tests -v
python -m offline_sequence_benchmarks --profile smoke
```

Подробности офлайн-стенда: [`offline_sequence_benchmarks/README.md`](../offline_sequence_benchmarks/README.md).

### Подбор гиперпараметров (Optuna)

```bash
pip install -r live_test_runner/requirements.txt
python -m live_test_runner.optuna_tune --trials 36 --budget 240 --horizon 24
```

Optuna (TPE) максимизирует на офлайн-буклете:

```text
score = unique_paths + unique_transitions + 20 * findings + code_vulnerabilities
```

- `unique_paths` — число уникальных маршрутов до открытых состояний  
- `unique_transitions` — число уникальных рёбер графа  
- `findings` — на буклете: достигнутые proof-страницы (`*-proof`); в live — `problems_unique`  
- `code_vulnerabilities` — число находок Bandit по `--source-dir` (статический анализ кода)

`code_vulnerabilities` одинаков для всех trial одного source, поэтому на сравнение Q vs GA почти не влияет, но входит в итоговую метрику эксперимента. Разность с Random **не** оптимизируется.

Лучшие параметры пишутся в [`live_test_runner/hyperparams.json`](../live_test_runner/hyperparams.json).

## Границы и ограничения

- Нужно **уже работающее** HTTP-приложение; раннер сам репозиторий не собирает и не деплоит.
- Нет Playwright: тяжёлый JS/SPA почти не обходится.
- Auth-wall (как у PyGoat без логина) сильно сужает покрытие.
- Не интегрирован в форму скана, worker и `manifest` продуктового UI.
- Не передаёт найденные последовательности в ZAP.

Краткий README пакета: [`live_test_runner/README.md`](../live_test_runner/README.md).
