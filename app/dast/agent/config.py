from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from app.core.config import get_settings, load_yaml_settings


@dataclass(frozen=True)
class PentestConfig:
    enabled: bool = True
    max_steps: int = 12
    max_seconds: int = 120
    max_requests: int = 200
    request_timeout: float = 8.0
    delay_seconds: float = 0.15
    max_pages: int = 8
    max_params: int = 12
    allow_private_targets: bool = False
    llm_enabled: bool = True
    llm_model: str = "baidu/ernie-5.5-flash-preview:free"
    llm_base_url: str = "https://openrouter.ai/api/v1"
    llm_api_key: str | None = None
    llm_timeout: float = 60.0


def _num(raw: dict[str, Any], key: str, default: Any) -> Any:
    val = raw.get(key, default)
    try:
        return type(default)(val)
    except (TypeError, ValueError):
        return default


def load_pentest_config(overrides: dict[str, Any] | None = None) -> PentestConfig:
    settings = get_settings()
    yaml_cfg = load_yaml_settings(settings.settings_path)
    raw: dict[str, Any] = dict((yaml_cfg.get("dast") or {}).get("pentest") or {})
    if overrides:
        raw.update({k: v for k, v in overrides.items() if v is not None})

    api_key = (
        os.getenv("OPENROUTER_API_KEY")
        or os.getenv("AI_API_KEY")
        or settings.ai_api_key
    )
    base_url = os.getenv("IRIS_PENTEST_LLM_BASE_URL") or str(
        raw.get("llm_base_url") or settings.ai_base_url or "https://openrouter.ai/api/v1"
    )
    model = os.getenv("IRIS_PENTEST_LLM_MODEL") or str(
        raw.get("llm_model") or "baidu/ernie-5.5-flash-preview:free"
    )
    if model and not model.endswith(":free"):
        raise ValueError(
            f"pentest agent is free-models-only: {model!r} must end with ':free'"
        )

    llm_enabled = bool(raw.get("llm_enabled", True))
    if os.getenv("PENTEST_LLM_ENABLED") is not None:
        llm_enabled = os.getenv("PENTEST_LLM_ENABLED", "").lower() in {"1", "true", "yes", "on"}

    return PentestConfig(
        enabled=bool(raw.get("enabled", True)),
        max_steps=_num(raw, "max_steps", 12),
        max_seconds=_num(raw, "max_seconds", 120),
        max_requests=_num(raw, "max_requests", 200),
        request_timeout=float(raw.get("request_timeout") or 8.0),
        delay_seconds=float(raw.get("delay_seconds") or 0.15),
        max_pages=_num(raw, "max_pages", 8),
        max_params=_num(raw, "max_params", 12),
        allow_private_targets=bool(raw.get("allow_private_targets", False)),
        llm_enabled=llm_enabled,
        llm_model=model,
        llm_base_url=base_url.rstrip("/"),
        llm_api_key=api_key,
        llm_timeout=float(raw.get("llm_timeout") or 60.0),
    )
