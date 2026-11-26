# Как тестировать security pipeline: разбор на реальном репозитории

Выбранный репозиторий: **[adzerk/purposefully-vulnerable-repo](https://github.com/adzerk/purposefully-vulnerable-repo)**
(Flask + SQLite, 3 файла кода; внутри намеренно оставлены SQLi, инъекция команд,
path traversal, секрет в коде). Он хорошо подходит для проверки всех сценариев:
маленький, без MySQL/Django-миграций, запускается одной командой и при этом имеет
защищённые сессией эндпоинты (`/users`, `/files/download`, `/diag/ping`) — то есть
проверяет и аутентификацию, и привязку гипотез к маршрутам.

Все команды — из корня `FSTEC_sys` в PowerShell.

---

## 0. Подготовка цели (один раз)

```powershell
$t = "C:\Users\Mukharyam\PycharmProjects\_targets\pvr"
git clone --depth 1 https://github.com/adzerk/purposefully-vulnerable-repo $t

cd $t
py -3.11 -m venv .venv
.\.venv\Scripts\pip install flask pyyaml requests pillow paramiko
.\.venv\Scripts\python app.py
```

Ожидаемо: `Running on http://127.0.0.1:5000` (Flask 3.x, SQLite создаётся сам).
Терминал не закрывать.

Проверка, что цель жива (второй терминал):

```powershell
curl.exe -sS -o NUL -w "%{http_code}`n" http://127.0.0.1:5000/login   # 200
```

---

## Сценарий A — только ревью кода (без запущенного приложения)

```powershell
cd C:\Users\Mukharyam\PycharmProjects\FSTEC_sys
.\.venv\Scripts\python -m app.security review `
  --repo C:\Users\Mukharyam\PycharmProjects\_targets\pvr `
  --no-llm --out data\security\pvr-review
```

### Что увидите при успехе

```
repo      : ...\pvr
target    : —
review    : deterministic (6 гипотез, файлов 3)
hypotheses: 6 (sast 0)
verdicts  : confirmed 0, refuted 0, uncertain 0, skipped 0 [0 проверок, 0 запросов]
findings  : 4
report    : data\security\pvr-review\security_review.md
json      : data\security\pvr-review\security_review.json
sarif     : data\security\pvr-review\security_review.sarif
```

Гипотезы (видно в JSON и в отчёте):

| класс | endpoint | param | файл:строка |
|---|---|---|---|
| sqli | `/login` | username | db.py:40 |
| sqli | `/users` | q | db.py:40 |
| sqli | `/register` | username | db.py:64 |
| cmd_injection | `/files/download` | file | app.py:134 |
| cmd_injection | `/diag/ping` | host | app.py:197 |

`findings` — это review-находки (`source: review-agent`) для мест, где есть
привязка к маршруту; остальные гипотезы остаются в разделе «без подтверждения».

---

## Сценарий B — проверка без логина (показывает ограничение)

```powershell
.\.venv\Scripts\python -m app.security scan `
  --repo C:\Users\Mukharyam\PycharmProjects\_targets\pvr `
  --url http://127.0.0.1:5000 --no-llm --allow-private `
  --out data\security\pvr-noauth
```

### Что увидите

```
verdicts  : confirmed 2, refuted 6, uncertain 0, skipped 1 [...]
top risks :
  P3 [low] missing_headers ...
  P3 [low] error_disclosure ...
```

То есть подтвердятся только те проверки, которые не требуют сессии. SQLi и
инъекция команд на `/users`, `/files/download`, `/diag/ping` будут `refuted`,
потому что приложение редиректит на `/login` (`302`), а не выполняет запрос.
Это **ожидаемое** поведение, а не баг: нужен сценарий входа (сценарий C).

---

## Сценарий C — полный прогон с аутентификацией (основной)

Приложение не содержит пользователей, поэтому pipeline сначала регистрирует
пользователя, затем логинится и только потом проверяет защищённые эндпоинты:

```powershell
.\.venv\Scripts\python -m app.security scan `
  --repo C:\Users\Mukharyam\PycharmProjects\_targets\pvr `
  --url http://127.0.0.1:5000 --no-llm --allow-private `
  --auth-user pentest01 --auth-pass Pentest123 --auth-register-url /register `
  --out data\security\pvr-scan
```

### Что увидите при успехе

```
review    : deterministic (6 гипотез, файлов 3)
hypotheses: 11 (sast 0)
verdicts  : confirmed 7, refuted 3, uncertain 0, skipped 1 [38 проверок, 71 запрос]
top risks :
  P0 [critical] cmd_injection   app.py:197   http://127.0.0.1:5000/diag/ping
  P1 [high]     sqli            db.py:40     http://127.0.0.1:5000/login
  P1 [high]     sqli            db.py:40     http://127.0.0.1:5000/users?q=%27
  P1 [high]     sqli            db.py:64     http://127.0.0.1:5000/register
  P3 [low]      missing_headers —            http://127.0.0.1:5000/
  P3 [low]      error_disclosure —           http://127.0.0.1:5000/api/token
findings  : 8
```

`exit code = 0`. В `meta.verification` будет `"authenticated": true`.

Почему именно столько:
- SQLi подтверждается ошибкой SQLite в ответе (детектор ловит
  `sqlite3.OperationalError`/`unrecognized token`);
- command injection на `/diag/ping` — маркер команды в выводе (`| echo ...`);
- `/files/download` остаётся неподтверждённым: приложение печатает только
  `Exit code`, а не stdout команды (слепая RCE — нужен time-based детектор,
  см. «Ограничения»);
- headers/error disclosure — проверки уровня цели.

---

## Сценарий D — только проверка готовых гипотез (`verify`)

Полезно, когда ревью уже сделано, а цель подняли позже (например, в песочнице):

```powershell
.\.venv\Scripts\python -m app.security verify `
  --repo C:\Users\Mukharyam\PycharmProjects\_targets\pvr `
  --url http://127.0.0.1:5000 `
  --hypotheses data\security\pvr-review\security_review.json `
  --allow-private --auth-user pentest02 --auth-pass Pentest123 `
  --auth-register-url /register --out data\security\pvr-verify
```

Ожидаемо: `confirmed 4` (три SQLi + command injection), без повторного ревью.
`review` при этом не запускается — режим `verify-only`.

---

## Сценарий E — с бесплатной LLM (Groq)

Полный разбор провайдеров и получение ключей — в [LLM_PROVIDERS.md](LLM_PROVIDERS.md).
Коротко: Groq даёт ~1 000 запросов/день бесплатно, ключ берётся в
<https://console.groq.com> → API Keys.

```powershell
$env:GROQ_API_KEY = "gsk_..."
.\.venv\Scripts\python -m app.security review `
  --repo C:\Users\Mukharyam\PycharmProjects\_targets\pvr `
  --llm-provider groq --llm-model openai/gpt-oss-120b `
  --out data\security\pvr-llm
```

Ожидаемо при рабочем ключе и свободной квоте:

```
review    : llm-direct (6 гипотез, файлов 3)
llm       : groq / openai/gpt-oss-120b [key: yes]
findings  : 6
```

В отчёте `mode: llm-direct`, гипотезы с `source: llm_review` (плюс сильные
детерминированные кандидаты). Если ключа нет/квота кончилась/модель стабильно
ломает JSON — будет `review : deterministic`, `llm : ... [key: no]` или
`llm error : ...`, и скан не упадёт (fallback).

Для агентного режима (сама вызывает `read_file/grep/...`) добавьте
`--llm-provider groq` и `review_tool_mode: on` в конфиг — но на free-Groq
(8k TPM) это медленно и упирается в лимиты; direct-режим стабильнее.

GigaChat — альтернатива: `--llm-provider gigachat --llm-model GigaChat-2`
(нужен `GIGACHAT_CREDENTIALS`, см. LLM_PROVIDERS.md).

---

## Где смотреть результат

| Файл | Что внутри |
|---|---|
| `data\security\<out>\security_review.md` | топ рисков P0–P3, подтверждённые находки с payload/запросом/ответом, неподтверждённые гипотезы |
| `data\security\<out>\security_review.json` | `meta` (счётчики, `authenticated`), `hypotheses`, `verifications`, `findings` |
| `data\security\<out>\security_review.sarif` | SARIF 2.1.0 для CI/IDE |
| `data\security\<out>\security_review.md` (раздел «Гипотезы без динамического подтверждения») | что не проверялось и почему |

Ключевые поля JSON:

- `meta.verification`: `requests`, `ok_responses`, `confirmed/refuted/uncertain/skipped`, `authenticated`;
- `verifications[].verdict`, `.plugin`, `.payload`, `.url`, `.evidence`, `.judged_by`;
- `findings[].source`: `pentest` (подтверждено динамически) или `review-agent` (ревью кода).

---

## Что увидите при неудачном запуске

| Ситуация | Вывод | Exit |
|---|---|---|
| цель на localhost без `--allow-private` | `[FAIL] динамическая проверка не выполнена: DastTargetError: ... loopback addresses are blocked` + подсказка | 2 |
| приложение не запущено / неверный порт | `[FAIL] ни один запрос не дошёл до цели — проверьте URL и что приложение запущено` | 2 |
| репозиторий не найден | `[FAIL] репозиторий не найден: ...` | 2 |
| логин не удался (неверные креды) | в отчёте `authenticated: false`, защищённые проверки `refuted`/`skipped`; смотрите `meta.verification` | 0 |
| в конфиге платная модель | `ValueError: ... must end with ':free'` | 2 |
| нет ключа LLM | не ошибка: `review : deterministic`, `meta.review.llm_error` | 0 |
| скан упёрся в бюджет | `finish` нет; в `meta.verification` `skipped`, причина «бюджет запросов исчерпан» | 0 |

Важно: при любом сбое динамики **ревью-часть всё равно пишется** в отчёт
(находки `review-agent`) — это by design.

---

## Ограничения, которые видно на этом репозитории

1. **Слепая RCE**: `/files/download` выполняет команду, но возвращает только код
   возврата — подтвердить инъекцию по ответу нельзя. Нужен time-based детектор
   (`sleep`) или OOB-канал.
2. **Path traversal** там же не проверяется, потому что путь строится внутри
   `subprocess`-команды, а не отдаётся файлом; статическая гипотеза есть, динамика
   её не подтверждает.
3. **Crawl-фолбэк** может добавить вторую гипотезу для `/register` (поле `email`) —
   это отдельный инъекционный параметр того же запроса, не дубль.
4. Для эндпоинтов без сессии (`/login`, `/register`) достаточно `--allow-private`,
   для остальных нужен сценарий входа (сценарий C).

---

## Уборка

```powershell
# остановить приложение — Ctrl+C в его терминале
# удалить артефакты прогонов (по желанию)
Remove-Item -Recurse -Force data\security\pvr-*
```
