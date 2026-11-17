from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.core.config import get_settings, load_yaml_settings


@dataclass(frozen=True)
class AiSettings:
    enabled: bool
    provider: str
    base_url: str
    model: str
    api_key: str | None
    timeout_seconds: int
    max_files: int
    max_file_bytes: int
    max_findings: int


def _yaml_ai_section() -> dict[str, Any]:
    settings = get_settings()
    cfg = load_yaml_settings(settings.settings_path)
    raw = cfg.get("ai") or {}
    return raw if isinstance(raw, dict) else {}


def load_ai_settings() -> AiSettings:
    settings = get_settings()
    yaml_ai = _yaml_ai_section()

    yaml_enabled = bool(yaml_ai.get("enabled", False))
    if settings.ai_enabled is not None:
        yaml_enabled = bool(settings.ai_enabled)

    base_url = settings.ai_base_url or str(
        yaml_ai.get("base_url") or "https://api.openai.com/v1"
    )
    model = settings.ai_model or str(yaml_ai.get("model") or "gpt-4o-mini")

    return AiSettings(
        enabled=yaml_enabled,
        provider=str(yaml_ai.get("provider") or "openai_compatible"),
        base_url=base_url.rstrip("/"),
        model=model,
        api_key=(settings.ai_api_key or None),
        timeout_seconds=int(yaml_ai.get("timeout_seconds") or 120),
        max_files=int(yaml_ai.get("max_files") or 25),
        max_file_bytes=int(yaml_ai.get("max_file_bytes") or 40000),
        max_findings=int(yaml_ai.get("max_findings") or 50),
    )


def is_ai_enabled(enable_override: bool | None = None) -> bool:
    """Active only when config says on (or per-scan override) and API key exists."""
    cfg = load_ai_settings()
    if enable_override is False:
        return False
    want = cfg.enabled if enable_override is None else True
    return want and bool(cfg.api_key)
