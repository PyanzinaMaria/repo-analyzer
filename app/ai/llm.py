"""LLM client (spec §6.1): OpenAI-compatible backends, sqlite cache, rate/daily limits, cost log,
JSON extraction + validation with one repair retry, and an offline batch mode.

Modes:
  live    call the backend on cache miss
  export  on cache miss, append the request to data/llm_batch/<model>.requests.jsonl, return None
          (run scripts/kaggle_vllm_batch.py on a GPU box, then `python -m bench llm import`)
  cache   never call; cache misses return None (used by eval/report)
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import httpx
from pydantic import BaseModel, ValidationError

from app.core import io
from app.core.yaml_configs import ModelsConfig, ModelSpec, REPO_ROOT
from app.ai.schemas import SCHEMA_HINTS
from app.core.runlog import log

Mode = Literal["live", "export", "cache"]
OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"


class BudgetExceeded(RuntimeError):
    pass


class DailyLimitReached(RuntimeError):
    pass


class UpstreamUnavailable(RuntimeError):
    """The model's upstream provider is rate-limiting the shared free pool; try later or another model."""


# OpenRouter-specific request fields that the OpenAI SDK does not know; sent via extra_body.
EXTRA_BODY_KEYS = {"reasoning", "provider", "transforms", "top_k", "min_p", "repetition_penalty"}


def load_dotenv(path: Path = REPO_ROOT / ".env") -> None:
    """Minimal .env loader (KEY=VALUE lines); does not override existing env vars."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def model_slug(model_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", model_id)


def extract_json(text: str) -> dict | None:
    """First balanced JSON object in `text` (handles ``` fences and leading prose)."""
    if not text:
        return None
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    candidates = [fence.group(1)] if fence else []
    start = text.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidates.append(text[start:i + 1])
                    break
        start = text.find("{", start + 1) if not candidates else -1
    for c in candidates:
        try:
            obj = json.loads(c)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue
    return None


@dataclass
class CallResult:
    obj: BaseModel | None
    raw: str | None = None
    cached: bool = False
    pending: bool = False          # export mode: request queued for batch
    error: str | None = None
    cost: float = 0.0
    usage: dict = field(default_factory=dict)


class Cache:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False, timeout=60)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""CREATE TABLE IF NOT EXISTS responses (
            key TEXT PRIMARY KEY, model TEXT, created TEXT, text TEXT, usage TEXT, cost REAL)""")
        self._conn.execute("""CREATE TABLE IF NOT EXISTS daily (
            backend TEXT, day TEXT, n INTEGER, PRIMARY KEY (backend, day))""")
        self._conn.commit()

    def get(self, key: str) -> tuple[str, dict, float] | None:
        with self._lock:
            row = self._conn.execute("SELECT text, usage, cost FROM responses WHERE key=?", (key,)).fetchone()
        return (row[0], json.loads(row[1] or "{}"), row[2] or 0.0) if row else None

    def put(self, key: str, model: str, text: str, usage: dict, cost: float) -> None:
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO responses VALUES (?,?,?,?,?,?)",
                               (key, model, datetime.now(timezone.utc).isoformat(), text, json.dumps(usage), cost))
            self._conn.commit()

    def bump_daily(self, backend: str) -> int:
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        with self._lock:
            self._conn.execute("INSERT INTO daily VALUES (?,?,1) ON CONFLICT(backend, day) DO UPDATE SET n=n+1",
                               (backend, day))
            self._conn.commit()
            return self._conn.execute("SELECT n FROM daily WHERE backend=? AND day=?", (backend, day)).fetchone()[0]

    def daily_count(self, backend: str) -> int:
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        with self._lock:
            row = self._conn.execute("SELECT n FROM daily WHERE backend=? AND day=?", (backend, day)).fetchone()
        return row[0] if row else 0


class LLMClient:
    def __init__(self, cfg: ModelsConfig, mode: Mode = "live", data_root: Path | None = None,
                 budget_usd: float | None = None):
        """`data_root` holds llm_cache/ (sqlite cache), results/ (cost log) and llm_batch/ (export mode):
        the benchmark passes $SECBENCH_DATA, the server its data/ directory."""
        load_dotenv()
        self.cfg, self.mode = cfg, mode
        self.root = Path(data_root) if data_root is not None else REPO_ROOT / "data"
        self.cache = Cache(self.root / "llm_cache" / "cache.sqlite")
        self.budget = cfg.budget_usd if budget_usd is None else budget_usd
        self.spent = 0.0
        self._rate_lock = threading.Lock()
        self._last_call: dict[str, float] = {}
        self._models_meta: dict[str, dict] | None = None
        self._clients: dict[str, object] = {}
        self._export_lock = threading.Lock()

    # ------------------------------------------------------------------ models metadata

    def models_meta(self, refresh: bool = False) -> dict[str, dict]:
        """OpenRouter /models (cached on disk for a day)."""
        if self._models_meta is not None and not refresh:
            return self._models_meta
        path = self.root / "llm_cache" / "openrouter_models.json"
        fresh = path.exists() and time.time() - path.stat().st_mtime < 86400
        if not fresh or refresh:
            if self.mode == "cache" and path.exists():
                pass
            else:
                r = httpx.get(OPENROUTER_MODELS_URL, timeout=60)
                r.raise_for_status()
                io.write_json(path, r.json())
        data = io.read_json(path) if path.exists() else {"data": []}
        self._models_meta = {m["id"]: m for m in data.get("data", [])}
        return self._models_meta

    def verify_models(self) -> list[dict]:
        """Check every OpenRouter model id in models.yaml exists; return rows for display."""
        meta = self.models_meta(refresh=True)
        rows = []
        for m in self.cfg.models:
            info = meta.get(m.id) if m.backend == "openrouter" else None
            rows.append({"id": m.id, "backend": m.backend, "role": m.role,
                         "exists": (info is not None) if m.backend == "openrouter" else None,
                         "context": (info or {}).get("context_length"),
                         "prompt_price": ((info or {}).get("pricing") or {}).get("prompt"),
                         "completion_price": ((info or {}).get("pricing") or {}).get("completion")})
        io.write_json(self.root / "results" / "models_verified.json", rows)
        return rows

    def spec(self, model_id: str) -> ModelSpec:
        for m in self.cfg.models:
            if m.id == model_id:
                return m
        return ModelSpec(id=model_id, backend="openrouter")

    def _price(self, model_id: str) -> tuple[float, float]:
        if self.spec(model_id).backend != "openrouter":
            return 0.0, 0.0
        try:
            p = (self.models_meta().get(model_id) or {}).get("pricing") or {}
            return float(p.get("prompt") or 0), float(p.get("completion") or 0)
        except Exception:  # noqa: BLE001
            return 0.0, 0.0

    def _supports(self, model_id: str, param: str) -> bool:
        if self.spec(model_id).backend != "openrouter":
            return param == "response_format"
        try:
            return param in ((self.models_meta().get(model_id) or {}).get("supported_parameters") or [])
        except Exception:  # noqa: BLE001
            return False

    # ------------------------------------------------------------------ calling

    def _client(self, backend: str):
        if backend not in self._clients:
            from openai import OpenAI

            b = self.cfg.backends[backend]
            key = b.api_key or (os.environ.get(b.api_key_env, "") if b.api_key_env else "not-needed")
            if b.api_key_env and not key:
                raise RuntimeError(f"{b.api_key_env} is not set (put it in .env)")
            headers = {"X-Title": "repo-analyzer"} if backend == "openrouter" else None
            # Keep per-request timeout modest: hung OpenRouter free-pool calls
            # otherwise block the whole scan (UI stays on «Анализ») for many minutes.
            self._clients[backend] = OpenAI(base_url=b.base_url, api_key=key, default_headers=headers,
                                            timeout=60, max_retries=0)
        return self._clients[backend]

    def _respect_rate(self, backend: str) -> None:
        b = self.cfg.backends[backend]
        if b.requests_per_day and self.cache.daily_count(backend) >= b.requests_per_day:
            raise DailyLimitReached(f"{backend}: daily request limit {b.requests_per_day} reached")
        if not b.requests_per_minute:
            return
        gap = 60.0 / b.requests_per_minute
        with self._rate_lock:
            wait = self._last_call.get(backend, 0) + gap - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last_call[backend] = time.monotonic()

    def _call_backend(self, model_id: str, messages: list[dict], params: dict) -> tuple[str, dict]:
        from openai import APIConnectionError, APIStatusError, APITimeoutError, RateLimitError

        spec = self.spec(model_id)
        client = self._client(spec.backend)
        kwargs = {k: v for k, v in params.items() if k not in EXTRA_BODY_KEYS}
        extra = {k: v for k, v in params.items() if k in EXTRA_BODY_KEYS}
        if extra:
            kwargs["extra_body"] = extra
        if self._supports(model_id, "response_format"):
            kwargs.setdefault("response_format", {"type": "json_object"})
        # Keep retries short: a flaky OpenRouter free pool used to stall whole scans
        # for many minutes (6 attempts × up to 120s + 300s client timeout).
        delay = 2.0
        upstream_429 = 0
        conn_fails = 0
        for attempt in range(3):
            self._respect_rate(spec.backend)
            try:
                resp = client.chat.completions.create(model=model_id, messages=messages, **kwargs)
                self.cache.bump_daily(spec.backend)
                if not resp.choices:
                    raise RuntimeError(f"empty response: {getattr(resp, 'error', None)}")
                text = resp.choices[0].message.content or ""
                usage = resp.usage.model_dump() if resp.usage else {}
                return text, usage
            except RateLimitError as e:
                msg = str(e).lower()
                if "per-day" in msg or "free-models-per-day" in msg:
                    raise DailyLimitReached(str(e)[:300]) from e
                if "upstream" in msg:
                    # shared free pool of the upstream provider is exhausted: not our quota;
                    # retry a couple of times, then let the caller move on
                    upstream_429 += 1
                    if upstream_429 >= 2:
                        raise UpstreamUnavailable(f"{model_id}: rate-limited upstream (shared free pool)") from e
                else:
                    self.cache.bump_daily(spec.backend)
                err = e
            except APIStatusError as e:
                if e.status_code < 500 and e.status_code not in (408, 409):
                    if e.status_code == 400 and "response_format" in kwargs:
                        kwargs.pop("response_format")  # some providers reject json mode
                        continue
                    raise
                err = e
            except (APIConnectionError, APITimeoutError) as e:
                err = e
                conn_fails += 1
                if conn_fails >= 2:
                    raise UpstreamUnavailable(
                        f"{model_id}: connection errors, aborting LLM call"
                    ) from e
            log.warning("%s: transient error (attempt %d): %s", model_id, attempt + 1, str(err)[:200])
            time.sleep(delay)
            delay = min(delay * 2, 15)
        raise UpstreamUnavailable(f"{model_id}: giving up after retries: {err}")

    def _log_cost(self, model_id: str, tag: str, usage: dict, cost: float, cached: bool) -> None:
        path = self.root / "results" / "llm_costs.csv"
        path.parent.mkdir(parents=True, exist_ok=True)
        new = not path.exists()
        with open(path, "a", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            if new:
                w.writerow(["ts", "model", "tag", "prompt_tokens", "completion_tokens", "cost_usd", "cached"])
            w.writerow([datetime.now(timezone.utc).isoformat(), model_id, tag, usage.get("prompt_tokens", 0),
                        usage.get("completion_tokens", 0), f"{cost:.6f}", int(cached)])

    @staticmethod
    def request_key(model_id: str, messages: list[dict], params: dict) -> str:
        blob = json.dumps({"m": model_id, "msgs": messages, "p": params}, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(blob.encode()).hexdigest()

    def _export(self, key: str, model_id: str, messages: list[dict], params: dict) -> None:
        path = self.root / "llm_batch" / f"{model_slug(model_id)}.requests.jsonl"
        with self._export_lock:
            seen = getattr(self, "_exported", None)
            if seen is None:
                seen = self._exported = {}
            if path not in seen:
                seen[path] = {r["key"] for r in io.iter_jsonl(path)}
            if key in seen[path]:
                return
            io.append_jsonl(path, {"key": key, "model": model_id, "messages": messages, "params": params})
            seen[path].add(key)

    def chat(self, model_id: str, messages: list[dict], params: dict | None = None,
             tag: str = "") -> tuple[str | None, bool, bool, dict, float]:
        """-> (text, cached, pending, usage, cost)."""
        spec = self.spec(model_id)
        params = {"temperature": 0, "max_tokens": 2048, **spec.params, **(params or {})}
        params["max_tokens"] = int(params["max_tokens"]) + spec.reasoning_headroom
        key = self.request_key(model_id, messages, params)
        hit = self.cache.get(key)
        if hit is not None:
            self._log_cost(model_id, tag, hit[1], 0.0, True)
            return hit[0], True, False, hit[1], 0.0
        if self.mode == "cache":
            return None, False, False, {}, 0.0
        if self.mode == "export":
            self._export(key, model_id, messages, params)
            return None, False, True, {}, 0.0
        if self.spent >= self.budget and self._price(model_id) != (0.0, 0.0):
            raise BudgetExceeded(f"budget ${self.budget} exhausted")
        text, usage = self._call_backend(model_id, messages, params)
        pp, cp = self._price(model_id)
        cost = usage.get("prompt_tokens", 0) * pp + usage.get("completion_tokens", 0) * cp
        self.spent += cost
        self.cache.put(key, model_id, text, usage, cost)
        self._log_cost(model_id, tag, usage, cost, False)
        if self.spent > self.budget and cost > 0:
            raise BudgetExceeded(f"budget ${self.budget} exceeded (spent ${self.spent:.4f})")
        return text, False, False, usage, cost

    def complete_json(self, model_id: str, system: str, user: str, schema: type[BaseModel],
                      params: dict | None = None, tag: str = "") -> CallResult:
        """Ask for JSON matching `schema`; on parse/validation failure retry once with the error."""
        hint = SCHEMA_HINTS.get(schema.__name__, json.dumps(schema.model_json_schema()))
        sys_msg = system + "\n\nRespond with a single JSON object and nothing else. Schema:\n" + hint
        messages = [{"role": "system", "content": sys_msg}, {"role": "user", "content": user}]
        total_cost, cached_all = 0.0, True
        last_err = None
        for attempt in range(2):
            text, cached, pending, usage, cost = self.chat(model_id, messages, params, tag)
            total_cost += cost
            cached_all = cached_all and cached
            if pending:
                return CallResult(obj=None, pending=True)
            if text is None:
                return CallResult(obj=None, error="not in cache")
            obj = extract_json(text)
            try:
                if obj is None:
                    raise ValueError("no JSON object found in the answer")
                return CallResult(obj=schema.model_validate(obj), raw=text, cached=cached_all, cost=total_cost,
                                  usage=usage)
            except (ValidationError, ValueError) as e:
                last_err = str(e)[:800]
                messages = messages + [{"role": "assistant", "content": text[:4000]},
                                       {"role": "user", "content": "Your answer did not match the schema: "
                                        f"{last_err}\nReturn only the corrected JSON object."}]
        return CallResult(obj=None, raw=text, error=f"invalid output: {last_err}", cost=total_cost,
                          cached=cached_all)

    # ------------------------------------------------------------------ batch import

    def import_responses(self, path: Path) -> int:
        """Load {key, model, text, usage?} rows produced by scripts/kaggle_vllm_batch.py into the cache."""
        n = 0
        for row in io.iter_jsonl(path):
            if row.get("text") is None:
                continue
            self.cache.put(row["key"], row.get("model", ""), row["text"], row.get("usage") or {}, 0.0)
            n += 1
        return n
