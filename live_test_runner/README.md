# Live sequence runner

Живой HTTP-раннер поверх алгоритмов из `offline_sequence_benchmarks/`: строит граф пользовательских взаимодействий (ссылки и формы), ищет последовательности через Q-learning и генетический алгоритм, прогоняет их по цели и пишет метрики покрытия и проблем качества.

Полное описание: [`docs/LIVE_SEQUENCE_RUNNER.md`](../docs/LIVE_SEQUENCE_RUNNER.md).

## Быстрый старт (Docker, буклет)

```bash
docker compose -f live_test_runner/docker-compose.yml up --build
```

Сервисы: `webapp` (буклет на `:8080`) и `runner`.  
Метрики: `live_test_runner/output/smoke/metrics.json`.

Главное поле для человека — **`aggregates.problems_unique`** (и список `findings`).  
`problems_total` — сырые повторы срабатываний, не число разных багов.

Полный прогон:

```bash
# Windows PowerShell
$env:RUNNER_PROFILE="full"; docker compose -f live_test_runner/docker-compose.yml up --build
```

## Локально без Docker

```bash
pip install -r live_test_runner/requirements.txt
python live_test_runner/target/app.py   # терминал 1 — буклет :8080
python -m live_test_runner --profile smoke --base-url http://127.0.0.1:8080
```

Внешняя цель:

```bash
python -m live_test_runner --profile smoke --base-url http://127.0.0.1:5000 --start-path /login
```

## Метрики

В `metrics.json`:

- покрытие: `states`, `transitions`, `proofs`
- сырые срабатывания: `http_4xx`, `http_5xx`, `missing_security_headers`, `insecure_cookies`, `reflected_input`, `problems_total`
- дедуп: **`problems_unique`** и `findings[]` (`fingerprint = kind|detail`, `pages`, `occurrences`)
- код: **`code_vulnerabilities`** (+ `code_vulnerabilities_report` от Bandit по `--source-dir`)
- разбивка `by_method`, последовательности и графы

```bash
python -m live_test_runner --profile smoke --base-url http://127.0.0.1:5000 \
  --source-dir sandbox/dast/targets/purposefully-vulnerable-repo
```

## Гиперпараметры (Optuna)

Файл [`hyperparams.json`](hyperparams.json) — лучшие Q/GA после Optuna.  
Цель Optuna: максимизировать **`problems_unique`** на живом буклете.

```bash
python -m live_test_runner.optuna_tune --trials 24 --budget 100 --horizon 20
```

## Тесты

```bash
python -m unittest discover -s live_test_runner/tests -v
```
