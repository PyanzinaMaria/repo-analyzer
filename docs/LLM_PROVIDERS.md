# LLM-провайдеры для security pipeline: ключи, лимиты, переключение

Пайплайн больше не привязан к OpenRouter: `app/security/llm.py` умеет работать с
любым **OpenAI-совместимым** API (Groq, OpenRouter, Gemini, локальная Ollama) и с
**GigaChat** (OAuth2 + собственный REST). Провайдер выбирается конфигом/env/CLI.

## Что выбрать

| Провайдер | Бесплатно | Лимиты (ориентир) | Качество для ревью кода | Когда брать |
|---|---|---|---|---|
| **Groq** ⭐ | да, без карты | ~30 запросов/мин, ~1 000 запросов/день, ~200k токенов/день на модель (free) | высокое (`openai/gpt-oss-120b`, `llama-3.3-70b`) | **рекомендую по умолчанию** |
| **GigaChat** | freemium: 365 млн токенов (Lite 250M + Pro 40M и т.д.) | пакетами, зависят от тарифа | хорошее (GigaChat-2 / Pro) | если нужен российский провайдер и данные в РФ |
| OpenRouter `:free` | да | 50 запросов/день на общий пул | зависит от модели | уже настроен, но мало запросов |
| Gemini Flash | да (кроме EU/UK/CH; в РФ может быть недоступен) | ~15 запросов/мин, ~1 500/день | высокое | если есть доступ |
| Ollama (локально) | да, без лимитов | ограничено железом | зависит от модели | приватность, офлайн |

Источники: [лимиты Groq](https://console.groq.com/docs/rate-limits) (в кабинете —
актуальные для вашей организации), [тарифы GigaChat для физлиц](https://developers.sber.ru/docs/ru/gigachat/tariffs/individual-tariffs),
[Gemini API keys](https://aistudio.google.com/apikey). Цифры меняются — сверяйтесь с
кабинетом; для нас важно, что у Groq дневной лимит в 20 раз выше OpenRouter.

---

## 1. Groq: получить ключ (5 минут)

1. Откройте <https://console.groq.com> и войдите через Google/GitHub/e-mail.
2. Слева **API Keys** → **Create API Key** → имя, например `fstec-security`.
3. Скопируйте ключ (`gsk_...`) — он показывается один раз.
4. Пропишите его в окружение (PowerShell):

```powershell
setx GROQ_API_KEY "gsk_ваш_ключ"     # навсегда, для новых терминалов
# или только для текущего терминала:
$env:GROQ_API_KEY = "gsk_ваш_ключ"
```

5. Проверка (должен вернуться список моделей):

```powershell
curl.exe -sS https://api.groq.com/openai/v1/models `
  -H "Authorization: Bearer $env:GROQ_API_KEY" | Select-Object -First 1
```

6. Лимиты своей организации: <https://console.groq.com/settings/limits>.

**Модели, которые хорошо работают для ревью кода:**

- `openai/gpt-oss-120b` — по умолчанию в нашем конфиге (сильный reasoning);
- `llama-3.3-70b-versatile` — быстрый и стабильный JSON;
- `qwen/qwen3-32b` — если нужен другой стиль/язык.

Если модель ответила `404 model not found` — она могла быть выведена из free-пула,
проверьте список в консоли и поменяйте `llm_model`.

---

## 2. GigaChat: получить ключ

1. Откройте <https://developers.sber.ru/studio> → войдите (Sber ID).
2. Создайте проект → подключите **GigaChat API** (scope `GIGACHAT_API_PERS` для физлиц).
3. В настройках проекта получите **Client ID** и **Client Secret**
   (в интерфейсе часто уже есть готовая строка `Authorization key` — это
   base64 от `client_id:client_secret`).
4. Если строки нет, соберите её сами:

```powershell
$pair = "ВАШ_CLIENT_ID:ВАШ_CLIENT_SECRET"
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair))
```

5. Пропишите в окружение:

```powershell
setx GIGACHAT_CREDENTIALS "base64_строка_из_шага_3_или_4"
# опционально: setx GIGACHAT_SCOPE "GIGACHAT_API_PERS"
```

6. **Сертификаты.** GigaChat использует сертификаты Минцифры РФ. Варианты:
   - установить корневой сертификат Минцифры в Windows (рекомендуется);
   - либо разрешить небезопасный TLS только для этого провайдера:
     `llm_verify_ssl: false` в `config/security.yaml` (или
     `$env:SECURITY_LLM_VERIFY_SSL="false"`). Это отключает проверку TLS —
     используйте осознанно.

7. Важно по тарифам: с **1 сентября 2026** новые клиенты (и те, кто не покупал
   пакеты) оплачивают работу через cloud.ru; freemium-токены — для действующих
   клиентов/физлиц по условиям Sber. Проверьте актуальные условия на странице
   тарифов, прежде чем рассчитывать на бесплатный объём.

**Модели:** `GigaChat-2` (по умолчанию в пресете), `GigaChat`, `GigaChat-Pro`.

---

## 3. Gemini и Ollama (опционально)

**Gemini:** ключ — <https://aistudio.google.com/apikey>, env `GEMINI_API_KEY`,
base_url уже прописан в пресете (`.../v1beta/openai`). Учтите: бесплатный tier
недоступен в EU/UK/CH, в РФ может быть гео-ограничение; данные бесплатного tier
могут использоваться Google.

**Ollama:** установите, выполните `ollama pull qwen2.5-coder:7b`, `ollama serve` —
ключ не нужен, лимитов нет, всё локально. Медленнее на ноутбуке, но приватно.

---

## 4. Как переключить провайдера

Приоритет: **CLI-флаг → env → `config/security.yaml` → пресет по умолчанию**.

### Через конфиг (постоянно)

`config/security.yaml`:

```yaml
security:
  llm_enabled: true
  llm_provider: groq            # groq | gigachat | openrouter | gemini | ollama
  llm_model: openai/gpt-oss-120b
  # llm_base_url: ...           # необязательно, подставится из пресета
  llm_timeout: 90
  llm_max_retries: 3
  llm_json_mode: true
  llm_verify_ssl: true          # для GigaChat без сертификатов — false
```

### Через окружение (не коммитить ключи!)

```powershell
$env:GROQ_API_KEY = "gsk_..."
$env:SECURITY_LLM_PROVIDER = "groq"
$env:SECURITY_LLM_MODEL = "openai/gpt-oss-120b"
# $env:SECURITY_LLM_BASE_URL = "..."   # если свой шлюз
# $env:SECURITY_LLM_VERIFY_SSL = "false"  # только для GigaChat без сертификатов
```

### Через CLI (разовый прогон)

```powershell
.\.venv\Scripts\python -m app.security review `
  --repo C:\path\to\repo `
  --llm-provider groq --llm-model openai/gpt-oss-120b `
  --out data\security\review-llm
```

Проверить, что ключ подхватился, можно по строке `llm :` в выводе:

```
review    : llm (7 гипотез, файлов 3)
llm       : groq / openai/gpt-oss-120b [key: yes]
```

Если ключа нет — `[key: no]`, `review: deterministic`, и в `meta.review.llm_error`
будет причина. Скан при этом не падает.

---

## 5. Режимы ревью: `direct` и `tools`

| Режим | Как работает | Когда использовать |
|---|---|---|
| **`direct`** (по умолчанию, `review_tool_mode: off`) | Один запрос: модели отдаётся обзор репозитория (entrypoints, sinks, outline) + окна кода вокруг кандидатов; она возвращает JSON с гипотезами | бесплатный Groq (8k TPM), медленные/лимитированные провайдеры |
| **`tools`** (`review_tool_mode: on`) | Агентный цикл: модель сама вызывает `list_files/read_file/grep/...` через function calling, затем `submit` | платные ключи/высокие TPM, локальная Ollama, OpenRouter с большим лимитом |

Почему direct стал дефолтом: у free Groq лимит **8000 токенов/мин**, а агентный
цикл из 8–12 шагов упирается в него (429/413), при этом модель склонна
перечитывать один и тот же файл. Direct-режим укладывается в один запрос
(~4–5k токенов) и стабильно возвращает гипотезы; детерминированные кандидаты
всё равно попадают в промпт, а затем в результат.

```yaml
security:
  review_tool_mode: off   # off | on
```

---

## 6. Что изменилось в коде (и почему прошлые ошибки больше не фатальны)

Было: жёстко OpenRouter + `response_format=json_object`, один шанс на ответ.
Ответ модели с пропущенной запятой (`Expecting ',' delimiter`) ронял весь LLM-этап
в детерминированный fallback. Потом Groq отвечал
`400 tool_use_failed: Tool choice is none, but model called a tool`.

Стало (`app/security/llm.py`, `app/security/providers.py`, `code_review.py`):

- **провайдеры**: Groq / GigaChat / OpenRouter / Gemini / Ollama, ключи из env;
- **native function calling**: инструменты объявляются через `tools`, ответ с
  `tool_calls` нормализуется в `{action, args}`; ошибка `tool_use_failed`
  «спасается» из `failed_generation` (Groq присылает намерение модели в теле 400),
  а если спасти не удалось — запрос повторяется без tools;
- **JSON-ремонт**: markdown-обёртки, первый сбалансированный объект, trailing
  commas, «умные» кавычки; при необходимости модель просят вернуть только JSON;
- **учёт обрезки**: при `finish_reason=length` бюджет токенов удваивается;
- **лимиты**: 429 ждёт `Retry-After` (не дольше 30 с), 413/TPM уменьшает
  `max_tokens`; при недоступной цели проверки прекращаются после 5 ошибок;
- **GigaChat**: OAuth-токен (кэшируется), обновление по 401, `llm_verify_ssl`;
- **кэш** учитывает провайдера/base_url/набор инструментов;
- в отчёте видно `review.llm = {provider, model, base_url, key}` и `llm_error`.

---

## 6. Диагностика

| Симптом | Причина | Что делать |
|---|---|---|
| `llm : groq / ... [key: no]`, `review: deterministic` | ключ не в env | `$env:GROQ_API_KEY=...` и новый терминал |
| `HTTP 401` / `403` | ключ неверный/просрочен | пересоздать ключ в консоли |
| `HTTP 404 model not found` | модель недоступна в free-пуле | взять модель из списка в консоли |
| `HTTP 429` | лимит RPM/RPD | подождать; уменьшить `review_max_steps`/`max_tokens`; сменить модель |
| `JSON: no complete JSON object` после ретраев | модель стабильно ломает JSON | сменить модель (Groq `llama-3.3-70b` стабильнее), уменьшить объём наблюдений |
| `400 tool_use_failed` | модель вызвала инструмент без объявленных tools | уже обрабатывается (salvage/повтор); если повторяется — `review_tool_mode: off` |
| `review: llm-direct` | это норма: direct-режим, один запрос | — |
| `SSLCertVerificationError` (GigaChat) | нет сертификатов Минцифры | установить корневой сертификат или `llm_verify_ssl: false` |
| скан идёт, но `review: deterministic` при рабочем ключе | модель вернула пустой `submit` | посмотреть `meta.review.llm_error`; попробовать другую модель |

---

## 7. Проверено на живом Groq

Репозиторий `adzerk/purposefully-vulnerable-repo`, модель `openai/gpt-oss-120b`,
free tier:

```
review    : llm-direct (6 гипотез, файлов 3)
llm       : groq / openai/gpt-oss-120b [key: yes]
hypotheses: 10 (sast 0)
verdicts  : confirmed 6, refuted 4, uncertain 0, skipped 0 [45 проверок, 79 запросов]
```

Подтверждено: SQLi на `/login`, SQLi на `/register` (две точки в коде),
command injection на `/diag/ping`, отсутствие security-заголовков, раскрытие
stack trace на `/api/token`. Один запрос к LLM, без 429/413.

Если у вас `review: llm-direct` — это штатный режим; `llm error` в выводе
означает, что сработал fallback на детерминированное ревью (скан всё равно
завершится).

---

## 8. Безопасность

- ключи — только через переменные окружения или `.env` (не коммитить);
- `llm_verify_ssl: false` допустим только как временное решение;
- data free-tier Gemini может использоваться Google — не отправляйте туда
  чувствительный код; для закрытых репозиториев используйте GigaChat (по
  условиям Sber) или локальную Ollama.
