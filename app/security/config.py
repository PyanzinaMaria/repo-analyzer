from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.config import get_settings, load_yaml_settings


@dataclass(frozen=True)
class SecurityConfig:
    enabled: bool = True
    # code review (hypothesis generation)
    review_enabled: bool = True
    review_max_files: int = 12
    review_max_chars_per_file: int = 12000
    review_max_steps: int = 12
    review_max_hypotheses: int = 25
    review_max_repo_files: int = 2500
    review_tool_mode: str = "off"      # off = one-shot review over context; on = agentic tool loop
    review_guidance: str = ""
    # static analysis (SAST findings -> hypotheses)
    from_sast: bool = True
    # dynamic verification
    verify_enabled: bool = True
    verify_max_hypotheses: int = 20
    verify_max_requests: int = 200
    verify_max_seconds: int = 120
    verify_delay: float = 0.15
    verify_allow_private: bool = False
    # optional authentication so protected endpoints can be verified
    auth_enabled: bool = False
    auth_login_url: str = "/login"
    auth_username_field: str = "username"
    auth_password_field: str = "password"
    auth_username: str = ""
    auth_password: str = ""
    auth_register_url: str = ""
    auth_email_field: str = "email"
    auth_email: str = "pentest@example.com"
    # crawl fallback: hypothesise over the live surface when code mapping is absent
    crawl_fallback: bool = True
    crawl_max_pages: int = 8
    crawl_max_hypotheses: int = 40
    # plugins / strategies
    plugins: tuple[str, ...] = ()
    strategies: tuple[str, ...] = ("raw", "urlencode")
    # LLM (provider-agnostic: Groq / GigaChat / OpenRouter / Gemini / Ollama)
    llm_enabled: bool = True
    llm_provider: str = ""              # "" = detect from base_url
    llm_model: str = ""                 # "" = provider default
    llm_base_url: str = ""              # "" = provider default
    llm_api_key: str | None = None
    llm_timeout: float = 60.0
    llm_verify_ssl: bool = True
    llm_max_retries: int = 3
    llm_json_mode: bool = True
    judge_enabled: bool = True
    min_severity: str = "low"
    cache_path: str = "data/llm_cache/security.sqlite"


def _list(raw: Any, default: tuple[str, ...]) -> tuple[str, ...]:
    if isinstance(raw, list) and raw:
        return tuple(str(x) for x in raw)
    return default


def load_security_config(overrides: dict[str, Any] | None = None) -> SecurityConfig:
    settings = get_settings()
    # dedicated config file first (config-as-code, like promptfoo's yaml),
    # then the `security:` section of settings.yaml as a fallback.
    raw: dict[str, Any] = {}
    dedicated = repo_root() / "config" / "security.yaml"
    if dedicated.exists():
        try:
            import yaml

            loaded = yaml.safe_load(dedicated.read_text(encoding="utf-8")) or {}
            raw = dict(loaded.get("security") or loaded)
        except Exception:  # noqa: BLE001 - malformed config must not break scans
            raw = {}
    if not raw:
        yaml_cfg = load_yaml_settings(settings.settings_path)
        raw = dict(yaml_cfg.get("security") or {})
    if overrides:
        raw.update({k: v for k, v in overrides.items() if v is not None})

    from app.security.providers import PROVIDERS, detect_provider, env_key

    explicit_provider = os.getenv("SECURITY_LLM_PROVIDER") or str(raw.get("llm_provider") or "")
    # base_url: empty -> provider default (never inherit settings.ai_base_url,
    # which points to api.openai.com and would break Groq/GigaChat).
    base_url = os.getenv("SECURITY_LLM_BASE_URL") or str(raw.get("llm_base_url") or "")
    provider = detect_provider(base_url or None, explicit_provider or None)
    spec = PROVIDERS[provider]
    base_url = (base_url or spec.base_url).rstrip("/")

    model = os.getenv("SECURITY_LLM_MODEL") or str(raw.get("llm_model") or "") or spec.default_model
    if provider == "openrouter" and model and not model.endswith(":free"):
        raise ValueError(
            f"OpenRouter is free-models-only: {model!r} must end with ':free' "
            f"(use provider 'groq' for models without the suffix)"
        )

    api_key = (os.getenv("SECURITY_LLM_API_KEY") or str(raw.get("llm_api_key") or "")
               or env_key(spec) or "")
    if not api_key and provider == "openrouter":
        api_key = settings.ai_api_key or os.getenv("AI_API_KEY") or os.getenv("OPENROUTER_API_KEY") or ""

    verify_ssl = bool(raw.get("llm_verify_ssl", True))
    if os.getenv("SECURITY_LLM_VERIFY_SSL") is not None:
        verify_ssl = os.getenv("SECURITY_LLM_VERIFY_SSL", "").lower() in {"1", "true", "yes", "on"}

    llm_enabled = bool(raw.get("llm_enabled", True))
    if os.getenv("SECURITY_LLM_ENABLED") is not None:
        llm_enabled = os.getenv("SECURITY_LLM_ENABLED", "").lower() in {"1", "true", "yes", "on"}

    return SecurityConfig(
        enabled=bool(raw.get("enabled", True)),
        review_enabled=bool(raw.get("review_enabled", True)),
        review_max_files=int(raw.get("review_max_files", 12)),
        review_max_chars_per_file=int(raw.get("review_max_chars_per_file", 12000)),
        review_max_steps=int(raw.get("review_max_steps", 12)),
        review_max_hypotheses=int(raw.get("review_max_hypotheses", 25)),
        review_max_repo_files=int(raw.get("review_max_repo_files", 2500)),
        review_tool_mode=str(raw.get("review_tool_mode", "off")).lower(),
        review_guidance=str(raw.get("review_guidance") or ""),
        from_sast=bool(raw.get("from_sast", True)),
        verify_enabled=bool(raw.get("verify_enabled", True)),
        verify_max_hypotheses=int(raw.get("verify_max_hypotheses", 20)),
        verify_max_requests=int(raw.get("verify_max_requests", 200)),
        verify_max_seconds=int(raw.get("verify_max_seconds", 120)),
        verify_delay=float(raw.get("verify_delay", 0.15)),
        verify_allow_private=bool(raw.get("verify_allow_private", False)),
        auth_enabled=bool(raw.get("auth_enabled", False)),
        auth_login_url=str(raw.get("auth_login_url", "/login")),
        auth_username_field=str(raw.get("auth_username_field", "username")),
        auth_password_field=str(raw.get("auth_password_field", "password")),
        auth_username=str(raw.get("auth_username", "")),
        auth_password=str(raw.get("auth_password", "")),
        auth_register_url=str(raw.get("auth_register_url", "")),
        auth_email_field=str(raw.get("auth_email_field", "email")),
        auth_email=str(raw.get("auth_email", "pentest@example.com")),
        crawl_fallback=bool(raw.get("crawl_fallback", True)),
        crawl_max_pages=int(raw.get("crawl_max_pages", 8)),
        crawl_max_hypotheses=int(raw.get("crawl_max_hypotheses", 40)),
        plugins=_list(raw.get("plugins"), ()),
        strategies=_list(raw.get("strategies"), ("raw", "urlencode")),
        llm_enabled=llm_enabled,
        llm_provider=provider,
        llm_model=model,
        llm_base_url=base_url,
        llm_api_key=api_key or None,
        llm_timeout=float(raw.get("llm_timeout", 60.0)),
        llm_verify_ssl=verify_ssl,
        llm_max_retries=int(raw.get("llm_max_retries", 3)),
        llm_json_mode=bool(raw.get("llm_json_mode", True)),
        judge_enabled=bool(raw.get("judge_enabled", True)),
        min_severity=str(raw.get("min_severity", "low")),
        cache_path=str(raw.get("cache_path", "data/llm_cache/security.sqlite")),
    )


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]
