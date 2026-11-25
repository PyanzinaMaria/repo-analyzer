from __future__ import annotations

"""LLM provider presets (OpenAI-compatible ones + GigaChat).

The security pipeline talks to any OpenAI-compatible endpoint; GigaChat is the
exception (OAuth2 + its own REST shape), so it gets a dedicated adapter in
``llm.py`` while its endpoint/key metadata lives here.
"""

import os
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    base_url: str
    key_env: tuple[str, ...]
    default_model: str
    openai_compatible: bool = True
    free_only: bool = False          # only OpenRouter enforces the ":free" suffix
    supports_json_mode: bool = True
    supports_tools: bool = True     # native OpenAI function calling
    notes: str = ""
    extra_env: tuple[str, ...] = field(default_factory=tuple)


PROVIDERS: dict[str, ProviderSpec] = {
    "groq": ProviderSpec(
        name="groq",
        base_url="https://api.groq.com/openai/v1",
        key_env=("GROQ_API_KEY",),
        default_model="openai/gpt-oss-120b",
        notes="Free tier: ~30 RPM / 1 000 requests/day / 200k tokens/day per model "
              "(check console.groq.com → Limits). Fast, good for code review.",
    ),
    "gigachat": ProviderSpec(
        name="gigachat",
        base_url="https://gigachat.devices.sberbank.ru/api/v1",
        key_env=("GIGACHAT_CREDENTIALS", "GIGACHAT_CLIENT_SECRET"),
        default_model="GigaChat-2",
        openai_compatible=False,
        supports_tools=False,
        notes="OAuth2 (client_id:client_secret -> token). Freemium tokens for "
              "individuals; new clients since 01.09.2026 are billed via cloud.ru. "
              "Needs Russian trusted root certificates (or llm_verify_ssl: false).",
        extra_env=("GIGACHAT_CLIENT_ID", "GIGACHAT_SCOPE"),
    ),
    "openrouter": ProviderSpec(
        name="openrouter",
        base_url="https://openrouter.ai/api/v1",
        key_env=("OPENROUTER_API_KEY", "AI_API_KEY"),
        default_model="baidu/ernie-5.5-flash-preview:free",
        free_only=True,
        notes="Only ':free' models are allowed. 50 free requests/day on the shared pool.",
    ),
    "gemini": ProviderSpec(
        name="gemini",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        key_env=("GEMINI_API_KEY", "GOOGLE_API_KEY"),
        default_model="gemini-2.5-flash",
        notes="Free tier ~15 RPM / 1 500 requests/day for Flash; the free tier is "
              "not available in the EU/UK/CH (and may be geo-blocked in RU).",
    ),
    "ollama": ProviderSpec(
        name="ollama",
        base_url="http://127.0.0.1:11434/v1",
        key_env=(),
        default_model="qwen2.5-coder:7b",
        notes="Local, unlimited and private (no key). Needs `ollama serve`.",
    ),
}


def detect_provider(base_url: str | None = None, explicit: str | None = None) -> str:
    """Pick a provider: explicit name > host of base_url > 'openrouter'."""
    if explicit:
        name = explicit.strip().lower()
        if name in PROVIDERS:
            return name
        raise ValueError(f"unknown LLM provider: {explicit!r} (known: {', '.join(PROVIDERS)})")
    if base_url:
        host = (urlparse(base_url).hostname or "").lower()
        if "groq.com" in host:
            return "groq"
        if "sberbank.ru" in host or "gigachat" in host:
            return "gigachat"
        if "googleapis.com" in host:
            return "gemini"
        if host in {"127.0.0.1", "localhost"}:
            return "ollama"
        if "openrouter.ai" in host:
            return "openrouter"
    return "openrouter"


def env_key(spec: ProviderSpec) -> str | None:
    for name in spec.key_env:
        value = os.getenv(name)
        if value:
            return value
    return None


def provider_public_info(name: str) -> dict[str, str]:
    spec = PROVIDERS.get(name)
    if spec is None:
        return {}
    return {
        "provider": spec.name,
        "base_url": spec.base_url,
        "default_model": spec.default_model,
        "key_env": ", ".join(spec.key_env) or "(no key)",
        "notes": spec.notes,
    }
