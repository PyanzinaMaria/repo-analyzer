from __future__ import annotations

"""LLM client for the security pipeline.

Supports any OpenAI-compatible provider (Groq, OpenRouter, Gemini, local Ollama)
and GigaChat (OAuth2 + its own REST shape). Provider presets live in
``providers.py``; this module handles transport, retries, JSON repair and the
on-disk cache.

Robustness matters more than elegance here: free models routinely return
slightly broken JSON (missing commas, smart quotes, truncation). Instead of
failing the whole review, the client repairs the text, asks the model to fix it,
or retries with a larger token budget.
"""

import base64
import hashlib
import json
import logging
import re
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from app.security.config import SecurityConfig, repo_root
from app.security.providers import PROVIDERS, ProviderSpec, detect_provider, env_key

logger = logging.getLogger(__name__)

GIGACHAT_OAUTH_URL = "https://ngw.devices.sberbank.ru:9443/api/v2/oauth"
_TOKEN_CACHE: dict[str, tuple[str, float]] = {}


class SecurityLlmError(RuntimeError):
    """Any LLM failure (transport, HTTP, unparsable answer)."""


class SecurityLlmHttpError(SecurityLlmError):
    def __init__(self, status: int, body: str, retry_after: float | None = None) -> None:
        super().__init__(f"HTTP {status}: {body[:300]}")
        self.status = status
        self.body = body
        self.retry_after = retry_after


@dataclass
class Completion:
    content: str
    finish_reason: str = ""
    tool_calls: list[dict[str, Any]] | None = None
    raw: dict[str, Any] | None = None


class SecurityLlm:
    def __init__(self, cfg: SecurityConfig, *, cache: bool = True,
                 transport: httpx.BaseTransport | None = None) -> None:
        self.cfg = cfg
        self.cache_enabled = cache
        self.transport = transport
        self.provider = detect_provider(cfg.llm_base_url, cfg.llm_provider or None)
        self.spec: ProviderSpec = PROVIDERS[self.provider]
        self.base_url = (cfg.llm_base_url or self.spec.base_url).rstrip("/")
        self.model = cfg.llm_model or self.spec.default_model
        self.api_key = cfg.llm_api_key or env_key(self.spec)
        self.verify_ssl = cfg.llm_verify_ssl
        self.json_mode = cfg.llm_json_mode

        self._cache_path = Path(cfg.cache_path)
        if not self._cache_path.is_absolute():
            self._cache_path = repo_root() / self._cache_path
        if cache:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_db()

    # ------------------------------------------------------------------ info
    @property
    def available(self) -> bool:
        if self.provider == "ollama":
            return True
        if self.provider == "gigachat":
            return bool(self.api_key)
        return bool(self.api_key)

    def info(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "base_url": self.base_url,
            "model": self.model,
            "json_mode": self.json_mode,
            "verify_ssl": self.verify_ssl,
            "key": bool(self.api_key) or self.provider == "ollama",
        }

    # ------------------------------------------------------------------ cache
    def _init_db(self) -> None:
        with sqlite3.connect(self._cache_path) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS llm_cache ("
                " key TEXT PRIMARY KEY, model TEXT, created REAL, payload TEXT)"
            )
            conn.commit()

    def _key(self, messages: list[dict[str, str]], max_tokens: int,
             tools: list[dict[str, Any]] | None = None) -> str:
        tool_names = [t.get("function", {}).get("name") for t in (tools or [])]
        raw = json.dumps({"p": self.provider, "b": self.base_url, "m": self.model,
                          "msgs": messages, "t": max_tokens, "tools": tool_names},
                         sort_keys=True)
        return hashlib.sha1(raw.encode()).hexdigest()

    def _cache_get(self, key: str) -> dict[str, Any] | None:
        if not self.cache_enabled:
            return None
        try:
            with sqlite3.connect(self._cache_path) as conn:
                row = conn.execute("SELECT payload FROM llm_cache WHERE key = ?", (key,)).fetchone()
            if row:
                return json.loads(row[0])
        except (sqlite3.Error, json.JSONDecodeError) as exc:  # noqa: BLE001
            logger.debug("cache read failed: %s", exc)
        return None

    def _cache_put(self, key: str, payload: dict[str, Any]) -> None:
        if not self.cache_enabled:
            return
        try:
            with sqlite3.connect(self._cache_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO llm_cache (key, model, created, payload) VALUES (?,?,?,?)",
                    (key, self.model, time.time(), json.dumps(payload, ensure_ascii=False)),
                )
                conn.commit()
        except sqlite3.Error as exc:  # noqa: BLE001
            logger.debug("cache write failed: %s", exc)

    # ------------------------------------------------------------------- chat
    def chat_json(
        self,
        messages: list[dict[str, str]],
        *,
        max_tokens: int = 2500,
        temperature: float = 0.0,
        retries: int | None = None,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: dict[str, Any] | str | None = None,
    ) -> dict[str, Any]:
        """Return parsed JSON/action; repairs/retries instead of failing on one bad answer.

        When ``tools`` is provided and the provider supports function calling, the
        model may answer with a native tool call; it is normalised to
        ``{"action": <name>, "args": {...}}`` so the agent loop does not care which
        transport the model chose.
        """
        if not self.available:
            raise SecurityLlmError(
                f"LLM provider '{self.provider}' has no key "
                f"(expected {', '.join(self.spec.key_env) or 'no key'})"
            )
        attempts = self.cfg.llm_max_retries if retries is None else retries
        tokens = max_tokens
        convo = list(messages)
        active_tools = tools if (tools and self.spec.supports_tools) else None
        key = self._key(convo, tokens, active_tools)
        cached = self._cache_get(key)
        if cached is not None:
            return cached

        last_error = ""
        for attempt in range(max(1, attempts + 1)):
            try:
                completion = self._complete(convo, tokens, temperature, active_tools, tool_choice)
            except SecurityLlmHttpError as exc:
                last_error = str(exc)
                if exc.status in {401, 402, 403}:
                    raise SecurityLlmError(last_error) from exc
                if exc.status == 429:
                    wait = min(30.0, exc.retry_after or (5.0 * (attempt + 1)))
                    logger.warning("LLM rate limit (%s), waiting %.0fs", self.provider, wait)
                    time.sleep(wait)
                    continue
                if exc.status == 413 or "tokens per minute" in exc.body.lower():
                    # request too large for the free TPM budget: shrink and retry
                    tokens = max(600, tokens // 2)
                    logger.warning("LLM token limit hit (%s); retrying with max_tokens=%s",
                                   self.provider, tokens)
                    continue
                if exc.status == 400 and "tool_use_failed" in exc.body:
                    # Groq validates tool calls even when tools were not requested;
                    # the body still carries the model's intended call.
                    salvaged = _salvage_tool_failure(exc.body)
                    if salvaged is not None:
                        self._cache_put(key, salvaged)
                        return salvaged
                    active_tools = None
                    convo = list(messages) + [{
                        "role": "user",
                        "content": "Не вызывай функции. Верни ТОЛЬКО JSON-объект вида "
                                   '{"action": "list_files|read_file|grep|submit|finish", "args": {...}}.',
                    }]
                    continue
                if exc.status == 400 and self.json_mode:
                    # some models reject response_format=json_object
                    self.json_mode = False
                    continue
                time.sleep(1.5 * (attempt + 1))
                continue
            except httpx.HTTPError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                time.sleep(1.5 * (attempt + 1))
                continue

            if completion.tool_calls:
                call = completion.tool_calls[0]
                data = _tool_call_to_action(call)
                # tool-call ids are request-scoped: do not cache them
                data["_tool_call"] = call
                return data

            try:
                data = parse_json_object(completion.content)
                data = _normalize_action_shape(data)
                self._cache_put(key, data)
                return data
            except ValueError as exc:
                last_error = f"JSON: {exc}"
                snippet = (completion.content or "")[:2000]
                logger.warning("unparsable JSON from %s (%s), retrying", self.provider, exc)
                if completion.finish_reason == "length":
                    tokens = min(tokens * 2, 8000)
                    convo = list(messages)
                    convo.append({
                        "role": "user",
                        "content": "Предыдущий ответ обрезан по лимиту токенов. "
                                   "Верни ответ короче и строго валидным JSON.",
                    })
                else:
                    convo = list(messages) + [
                        {"role": "assistant", "content": snippet},
                        {"role": "user", "content":
                            "Это невалидный JSON (пропущены кавычки/запятые или есть лишний текст). "
                            "Верни ТОЛЬКО валидный JSON-объект, без markdown и пояснений."},
                    ]
        raise SecurityLlmError(last_error or "unknown LLM error")

    # -------------------------------------------------------------- transport
    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if self.provider == "openrouter":
            headers.setdefault("HTTP-Referer", "https://localhost/fstec-security")
            headers.setdefault("X-Title", "FSTEC security pipeline")
        return headers

    def _complete(self, messages: list[dict[str, str]], max_tokens: int,
                  temperature: float,
                  tools: list[dict[str, Any]] | None = None,
                  tool_choice: dict[str, Any] | str | None = None) -> Completion:
        if self.provider == "gigachat":
            return self._complete_gigachat(messages, max_tokens, temperature)
        return self._complete_openai(messages, max_tokens, temperature, tools, tool_choice)

    def _complete_openai(self, messages: list[dict[str, str]], max_tokens: int,
                         temperature: float,
                         tools: list[dict[str, Any]] | None = None,
                         tool_choice: dict[str, Any] | str | None = None) -> Completion:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = tool_choice or "auto"
        if self.json_mode and self.spec.supports_json_mode and not tools:
            body["response_format"] = {"type": "json_object"}
        with httpx.Client(timeout=self.cfg.llm_timeout, trust_env=False,
                          verify=self.verify_ssl, transport=self.transport) as client:
            resp = client.post(f"{self.base_url}/chat/completions",
                               headers=self._headers(), json=body)
        if resp.status_code >= 400:
            retry_after = None
            try:
                retry_after = float(resp.headers.get("retry-after", ""))
            except (TypeError, ValueError):
                pass
            raise SecurityLlmHttpError(resp.status_code, resp.text, retry_after)
        data = resp.json()
        try:
            choice = data["choices"][0]
            message = choice["message"]
            return Completion(
                content=message.get("content") or "",
                finish_reason=str(choice.get("finish_reason") or ""),
                tool_calls=message.get("tool_calls") or None,
                raw=data,
            )
        except (KeyError, IndexError, TypeError) as exc:
            raise SecurityLlmError(f"unexpected response shape: {exc}") from exc

    # -------------------------------------------------------------- gigachat
    def _complete_gigachat(self, messages: list[dict[str, str]], max_tokens: int,
                           temperature: float) -> Completion:
        token = self._gigachat_token()
        body = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        with httpx.Client(timeout=self.cfg.llm_timeout, trust_env=False,
                          verify=self.verify_ssl, transport=self.transport) as client:
            resp = client.post(f"{self.base_url}/chat/completions",
                               headers={"Authorization": f"Bearer {token}",
                                        "Content-Type": "application/json"},
                               json=body)
        if resp.status_code == 401:  # token expired mid-flight
            _TOKEN_CACHE.pop(self.api_key or "", None)
            token = self._gigachat_token()
            with httpx.Client(timeout=self.cfg.llm_timeout, trust_env=False,
                              verify=self.verify_ssl, transport=self.transport) as client:
                resp = client.post(f"{self.base_url}/chat/completions",
                                   headers={"Authorization": f"Bearer {token}",
                                            "Content-Type": "application/json"},
                                   json=body)
        if resp.status_code >= 400:
            raise SecurityLlmHttpError(resp.status_code, resp.text)
        data = resp.json()
        choice = data["choices"][0]
        return Completion(content=choice["message"]["content"],
                          finish_reason=str(choice.get("finish_reason") or ""), raw=data)

    def _gigachat_token(self) -> str:
        cache_key = self.api_key or ""
        cached = _TOKEN_CACHE.get(cache_key)
        if cached and cached[1] > time.time() + 30:
            return cached[0]

        creds = self.api_key
        if not creds:
            raise SecurityLlmError("GIGACHAT_CREDENTIALS is empty")
        if ":" in creds and not _looks_like_base64(creds):
            creds = base64.b64encode(creds.encode()).decode()

        headers = {
            "Authorization": f"Basic {creds}",
            "RqUID": str(uuid.uuid4()),
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        with httpx.Client(timeout=self.cfg.llm_timeout, trust_env=False,
                          verify=self.verify_ssl, transport=self.transport) as client:
            resp = client.post(GIGACHAT_OAUTH_URL, headers=headers,
                               data={"scope": "GIGACHAT_API_PERS"})
        if resp.status_code >= 400:
            raise SecurityLlmHttpError(resp.status_code, resp.text)
        data = resp.json()
        token = data.get("access_token")
        if not token:
            raise SecurityLlmError(f"GigaChat OAuth returned no access_token: {data}")
        expires_at = float(data.get("expires_at") or 0) / 1000.0 or (time.time() + 1500)
        _TOKEN_CACHE[cache_key] = (token, expires_at)
        return token


def _looks_like_base64(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9+/=_-]+", value)) and len(value) % 4 == 0


def _short_name(name: str) -> str:
    """`repo_browser.list_files` -> `list_files` (models invent namespaces)."""
    return name.split(".")[-1].strip()


def _tool_call_to_action(call: dict[str, Any]) -> dict[str, Any]:
    fn = call.get("function") or {}
    name = _short_name(str(fn.get("name") or ""))
    raw_args = fn.get("arguments")
    args: dict[str, Any] = {}
    if isinstance(raw_args, dict):
        args = raw_args
    elif isinstance(raw_args, str) and raw_args.strip():
        try:
            args = parse_json_object(raw_args)
        except ValueError:
            args = {}
    return {"action": name, "args": args, "thought": ""}


def _normalize_action_shape(data: dict[str, Any]) -> dict[str, Any]:
    """Accept `{"name": ..., "arguments": ...}` as an action object too."""
    if "action" in data:
        return data
    if "name" in data:
        args = data.get("arguments") or data.get("args") or {}
        return {"action": _short_name(str(data["name"])),
                "args": args if isinstance(args, dict) else {},
                "thought": str(data.get("thought") or "")}
    return data


def _salvage_tool_failure(body: str) -> dict[str, Any] | None:
    """Groq returns 400 tool_use_failed but includes what the model wanted to call."""
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None
    err = payload.get("error") or {}
    if err.get("code") != "tool_use_failed":
        return None
    generated = err.get("failed_generation")
    if not isinstance(generated, str):
        return None
    try:
        data = parse_json_object(generated)
    except ValueError:
        return None
    return _normalize_action_shape(data)


# --------------------------------------------------------------------- parsing
def _strip_fences(text: str) -> str:
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
        text = text.lstrip()
    return text


def _balanced_object(text: str) -> str | None:
    """First balanced {...} block, ignoring braces inside strings."""
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def _repair(text: str) -> str:
    fixed = (text.replace("“", '"').replace("”", '"')
             .replace("‘", "'").replace("’", "'"))
    fixed = re.sub(r",\s*([}\]])", r"\1", fixed)          # trailing commas
    fixed = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", fixed)
    return fixed


def parse_json_object(content: str) -> dict[str, Any]:
    """Parse a JSON object from a model answer, repairing common breakage."""
    text = _strip_fences(content)
    candidate = _balanced_object(text)
    if candidate is None:
        raise ValueError("no complete JSON object (answer truncated or empty)")
    for attempt in (candidate, _repair(candidate)):
        try:
            data = json.loads(attempt)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            return data
        raise ValueError("model answer is not a JSON object")
    # last resort: raw_decode from the first brace (handles trailing prose)
    try:
        data, _ = json.JSONDecoder().raw_decode(candidate)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    raise ValueError("invalid JSON after repair")
