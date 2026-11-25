# DAST-бенчмарк: методика и запуск

Стадия F в CLI: `python -m bench dast up|scan|eval|down|compare`. Прогоняет живые DAST-сканеры
(ZAP, Wapiti, Nuclei, OWASP OFFAT, Nikto) против тех же корпусов, на которых считается SAST-бенчмарк
(`data/bench/owasp-java`, `owasp-python`, `realvuln`), и сводит метрики по ground truth корпусов.

## Наземная правда (ground truth)

| Корпус | Режим | Ground truth | Метрики |
|---|---|---|---|
| owasp-java (2740 тестов) | `owasp` | `expectedresults-1.2.csv`: каждый тест-кейс — HTTP-эндпоинт, метка true/false + CWE | TP/FP/FN, Precision/Recall/F1, TP-rate/FP-rate, разбивка по категориям и CWE |
| owasp-python (1230 тестов) | `owasp` | `expectedresults-0.1.csv`, аналогично | те же |
| realvuln (20 pinned-приложений) | `items` | ручные метки `ground-truth.json` (файл/строки, CWE) | Recall по приложениям (≥1 находки с пересекающимся CWE), Precision-прокси по находкам |

Сопоставление находок: `bench/dast/match.py`. Для OWASP URL находки -> `BenchmarkTestNNNNN` ->
метка CSV (endpoint-уровень, дедуп по имени теста); находки вне тестовых URL считаются FP и
отдельно учитываются в `non_test_findings`. Для realvuln — пересечение CWE с учётом семейств
(`cwe_overlap`). Согласованность CWE (`cwe_agreement`) считается только по находкам, у которых тул
указал CWE.

## Живые цели (`dast up`)

- **owasp-java** — двухэтапный docker-образ: `maven:3.9-eclipse-temurin-17` собирает WAR
  (`mvn clean package -DskipTests`, `target/benchmark.war`), рантайм `tomcat:9.0-jdk17-temurin`,
  HTTPS :8443 на self-signed `.keystore` из репозитория, WAR деплоится как ROOT. Разовая сборка
  ~20–40 минут, образ кэшируется (`dast-bench:owasp-java`) и переживает `dast down`.
- **owasp-python** — `python:3.11-slim` + `flask==3.1.0 ldap3`, `flask run --host 0.0.0.0 --port 5000`.
- **realvuln** — каждый item загружается продуктовым sandbox-раннером (`app/sandbox/runner.py`:
  compose/Dockerfile/heuristic-загрузка на сети `repo-analyzer-dast`); необучаемые приложения
  помечаются `boot_failed` и не сканируются.

Состояние целей — `dast/targets.json` в каталоге корпуса. Для dockerized-тулов (ZAP, Nikto)
используется container-DNS URL на общей сети; нативным тулам (Wapiti, Nuclei, OFFAT) отдаётся
host-published URL `127.0.0.1`.

## Тулы (`dast scan`)

| Тул | Способ запуска | Отчёт | CWE |
|---|---|---|---|
| ZAP | docker `zap-full-scan.py` (spider + active scan), `-T` = бюджет минут | `zap.json` | `cweid` из алертов |
| Wapiti | нативно, `pip install wapiti` (в venv бенчмарка) | `wapiti.json` | статическая карта классов атак (`WAPITI_CWE`) |
| Nuclei | нативный бинарник, `-severity low,medium,high,critical` (info-шаблоны исключены) | `nuclei.json` (JSONL) | `classification.cwe-id` шаблонов |
| OFFAT | нативно, `pip install offat`; нужен OpenAPI | `offat-report.json` | тесты OFFAT -> OWASP API Top 10 (грубая карта) |
| Nikto | docker `sullo/nikto:latest`, `-maxtime` = бюджет | `nikto.json` | в основном отсутствует (server-level сканер) |

Бюджет: `scan_timeout_s: 1800` (30 минут) на тул/цель (`config/dast.yaml`). Результаты кэшируются
(`*.status.json` + `*.findings.jsonl`), повторный запуск без `--force` их переиспользует.

### OpenAPI для OFFAT

OWASP Benchmark не публикует спецификацию, поэтому `dast up` генерирует её из пинов route-таблиц
снапшота (`@WebServlet` в Java, `@app.route` в Python: 2740/1230 эндпоинтов) —
`bench/dast/openapi.py`. Для realvuln спецификация ищется на живом приложении
(`/openapi.json`, `/swagger.json`, ...); нет спецификации -> тул пропущен с `no_openapi`.

## Метрики и отчёты (`dast eval`, `dast compare`)

- `results/dast_metrics.json` — per-tool: tp/fp/fn, precision/recall/f1, tp_rate/fp_rate,
  non_test_findings, cwe_agreement, время, разбивки `by_category`/`by_cwe` (OWASP) или
  recall_items (realvuln), плюс `coverage` по тулам.
- `results/dast_report.md` — таблицы по корпусу.
- `python -m bench dast compare data/bench/owasp-java data/bench/owasp-python data/bench/realvuln`
  -> `docs/DAST-BENCHMARK-COMPARISON.md` (отдельно от SAST-сводки `docs/BENCHMARK-COMPARISON.md`).

## Установка тулов

```bash
pip install -r requirements-bench.txt      # wapiti, offat (+ остальной research-стек)
# Nuclei: разово поставить бинарник в PATH (Windows amd64):
#   https://github.com/projectdiscovery/nuclei/releases -> nuclei_<ver>_windows_amd64.zip
nuclei -update-templates                    # разово скачать шаблоны
docker pull ghcr.io/zaproxy/zaproxy:stable  # подтянется при первом запуске
docker pull sullo/nikto:latest
```

## Полный прогон

```bash
SECBENCH_DATA=data/bench/owasp-python python -m bench dast up owasp-python
SECBENCH_DATA=data/bench/owasp-python python -m bench dast scan owasp-python
SECBENCH_DATA=data/bench/owasp-python python -m bench dast eval owasp-python
SECBENCH_DATA=data/bench/owasp-python python -m bench dast down owasp-python
```

Требуется Docker Desktop; ZAP/Nikto и цели должны видеть друг друга — сеть `repo-analyzer-dast`
создаётся автоматически. Ограничения: бюджет 30 минут ограничивает покрытие на 2740 эндпоинтах
(фиксируется в отчёте); Nikto — серверный сканер и по построению даёт большой `non_test_findings`;
Precision на realvuln — прокси (нет URL-уровня ground truth).

## Живой прогон: известные ограничения (первый полный прогон, 25.11.2026)

- **ZAP**: zap-full-scan пишет JSON только в самом конце и может не выйти чисто при лимите
  длительности (zaproxy#5040). Адаптер держит API на фиксированном порту 18090: если к концу
  бюджета отчёта нет, алерты выгружаются через `/JSON/core/view/alerts` (zap-partial.json),
  и только затем контейнер убивается. Первые числа (owasp-python, 1230 эндпоинтов, 43 мин):
  TP=64, FP=119, Recall 14%, Precision 35%, cwe-agree 54%.
- **Wapiti**: фаза crawl по всем 1230 эндпоинтам не укладывается в 30-минутный бюджет
  (--max-scan-time ограничивает не весь конвейер), отчёт пишется в конце — на больших
  корпусах тул не успевает и помечается failed; содержательные числа даёт на малых
  приложениях (realvuln).
- **Nuclei**: шаблонный сканер, на OWASP Benchmark честно даёт ~0 (нет известных
  CVE-фингерпринтов у синтетических тест-кейсов); сверять по non-CVE хитам не с чем.
- **OFFAT**: тесты «unrestricted endpoint» срабатывают на каждом эндпоинте спецификации:
  Recall 100% при Precision ~37% (все 452 true и все 778 false тестов помечены) — ожидаемое
  поведение для туловщины OWASP API Top 10 против синтетического бенчмарка; cwe-agree 0%
  из-за грубой карты тест->CWE.
- **Nikto**: 30-секундный проход по серверу, находки — заголовки/конфигурация сервера
  (non-test FP по построению).
- Docker Desktop на этой машине имеет ~7.6 ГБ в WSL2 VM: два параллельных ZAP + сборки
  клинивают движок (500 на API) — корпуса сканировать строго последовательно.
- **realvuln: 19 из 20 pinned-приложений не поднялись** песочницей (мёртвые пин-зависимости
  в Dockerfile, отсутствующие env-файлы у compose, java-репозитории без runnable-плана;
  у каждого — причина в `dast/targets.json`). Числа realvuln пока по одному приложению
  (rv-dvws-node); `dast up realvuln` идемпотентен и дособирает цели по мере правок sandbox.
  Доля незагрузки — сама по себе метрика пригодности sandbox для живых репозиториев.
