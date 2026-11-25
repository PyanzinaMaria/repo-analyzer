from __future__ import annotations

import json

import httpx
import pytest

from app.security.config import load_security_config
from app.security.llm import (
    GIGACHAT_OAUTH_URL,
    SecurityLlm,
    SecurityLlmError,
    parse_json_object,
)
from app.security.providers import detect_provider


def _cfg(**overrides):
    base = {"llm_enabled": True, "llm_provider": "groq",
            "llm_model": "openai/gpt-oss-120b", "llm_api_key": "test-key"}
    base.update(overrides)
    return load_security_config(base)


def _completion(content: str, finish: str = "stop") -> dict:
    return {"choices": [{"message": {"content": content}, "finish_reason": finish}]}


# ----------------------------------------------------------------- providers
def test_detect_provider_by_url_and_explicit():
    assert detect_provider("https://api.groq.com/openai/v1") == "groq"
    assert detect_provider("https://gigachat.devices.sberbank.ru/api/v1") == "gigachat"
    assert detect_provider("https://generativelanguage.googleapis.com/v1beta/openai") == "gemini"
    assert detect_provider("http://127.0.0.1:11434/v1") == "ollama"
    assert detect_provider("https://openrouter.ai/api/v1") == "openrouter"
    assert detect_provider(None, "groq") == "groq"
    with pytest.raises(ValueError):
        detect_provider(None, "unknown-provider")


def test_config_groq_defaults_and_key(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk-test")
    cfg = load_security_config({"llm_provider": "groq"})
    assert cfg.llm_base_url == "https://api.groq.com/openai/v1"
    assert cfg.llm_model == "openai/gpt-oss-120b"
    assert cfg.llm_api_key == "gsk-test"


def test_config_openrouter_still_free_only():
    with pytest.raises(ValueError):
        load_security_config({"llm_provider": "openrouter",
                              "llm_model": "openai/gpt-4o"})


# ------------------------------------------------------------------- parsing
def test_parse_json_object_variants():
    assert parse_json_object('{"a": 1}') == {"a": 1}
    assert parse_json_object('```json\n{"a": 1}\n```') == {"a": 1}
    assert parse_json_object('{"a": 1,}') == {"a": 1}
    assert parse_json_object('{"a": "x", "b": 2} trailing prose') == {"a": "x", "b": 2}
    assert parse_json_object('{"action": "submit", "args": {"hypotheses": []}}')["action"] == "submit"
    with pytest.raises(ValueError):
        parse_json_object('{"a": 1')


# ------------------------------------------------------------------ transport
def test_chat_json_groq_mock():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json=_completion('{"action": "finish"}'))

    llm = SecurityLlm(_cfg(), cache=False, transport=httpx.MockTransport(handler))
    data = llm.chat_json([{"role": "user", "content": "hi"}])
    assert data["action"] == "finish"
    assert seen["url"] == "https://api.groq.com/openai/v1/chat/completions"
    assert seen["auth"] == "Bearer test-key"
    assert seen["body"]["model"] == "openai/gpt-oss-120b"


def test_chat_json_repairs_bad_json_by_retrying():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, json=_completion('{"action": "finish" "args": {}}'))
        return httpx.Response(200, json=_completion('{"action": "finish", "args": {}}'))

    llm = SecurityLlm(_cfg(), cache=False, transport=httpx.MockTransport(handler))
    assert llm.chat_json([{"role": "user", "content": "x"}])["action"] == "finish"
    assert calls["n"] == 2


def test_chat_json_grows_budget_on_truncation():
    bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        if len(bodies) == 1:
            return httpx.Response(200, json=_completion('{"action": "sub', finish="length"))
        return httpx.Response(200, json=_completion('{"action": "finish", "args": {}}'))

    llm = SecurityLlm(_cfg(), cache=False, transport=httpx.MockTransport(handler))
    assert llm.chat_json([{"role": "user", "content": "x"}], max_tokens=100)["action"] == "finish"
    assert bodies[1]["max_tokens"] > bodies[0]["max_tokens"]


def test_chat_json_raises_without_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    cfg = load_security_config({"llm_provider": "groq", "llm_api_key": ""})
    llm = SecurityLlm(cfg, cache=False)
    assert not llm.available
    with pytest.raises(SecurityLlmError):
        llm.chat_json([{"role": "user", "content": "x"}])


# ------------------------------------------------------------------ gigachat
def test_tool_call_is_normalized_to_action():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{
            "message": {"content": None, "tool_calls": [{
                "id": "call_1", "type": "function",
                "function": {"name": "repo_browser.list_files",
                             "arguments": '{"pattern": ".*"}'},
            }]},
            "finish_reason": "tool_calls",
        }]})

    llm = SecurityLlm(_cfg(), cache=False, transport=httpx.MockTransport(handler))
    data = llm.chat_json([{"role": "user", "content": "x"}],
                         tools=[{"type": "function", "function": {"name": "list_files"}}])
    assert data["action"] == "list_files"
    assert data["args"] == {"pattern": ".*"}


def test_tool_use_failed_is_salvaged():
    body = json.dumps({"error": {
        "message": "Tool choice is none, but model called a tool",
        "code": "tool_use_failed",
        "failed_generation": '{"name": "repo_browser.read_file", '
                             '"arguments": {"file": "app.py", "start": 1}}',
    }})

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text=body)

    llm = SecurityLlm(_cfg(), cache=False, transport=httpx.MockTransport(handler))
    data = llm.chat_json([{"role": "user", "content": "x"}],
                         tools=[{"type": "function", "function": {"name": "read_file"}}])
    assert data["action"] == "read_file"
    assert data["args"]["file"] == "app.py"


def test_gigachat_oauth_and_chat(monkeypatch):
    from app.security import llm as llm_module

    llm_module._TOKEN_CACHE.clear()
    calls = {"oauth": 0, "chat": 0, "auth": None}

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == GIGACHAT_OAUTH_URL:
            calls["oauth"] += 1
            return httpx.Response(200, json={"access_token": "gc-token", "expires_at": 9e12})
        calls["chat"] += 1
        calls["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json=_completion('{"action": "finish"}'))

    cfg = load_security_config({
        "llm_provider": "gigachat", "llm_model": "GigaChat-2",
        "llm_api_key": "client:secret", "llm_verify_ssl": False,
    })
    llm = SecurityLlm(cfg, cache=False, transport=httpx.MockTransport(handler))
    assert llm.chat_json([{"role": "user", "content": "x"}])["action"] == "finish"
    assert calls["oauth"] == 1 and calls["chat"] == 1
    assert calls["auth"] == "Bearer gc-token"
