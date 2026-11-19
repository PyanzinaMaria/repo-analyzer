from __future__ import annotations

from dataclasses import dataclass, field
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
    # secaudit modes: review (file review), triage, discovery
    modes: tuple[str, ...] = ("review", "triage", "discovery")
    requests_per_minute: int | None = None
    requests_per_day: int | None = None
    max_concurrency: int = 1
    reasoning_headroom: int = 0
    params: dict = field(default_factory=dict)
    triage_max_findings: int = 10
    triage_per_prompt: int = 5
    triage_budget_tokens: int = 6000
    discovery_n_base: int = 6
    discovery_n_cap: int = 12
    discovery_per_prompt: int = 5
    discovery_budget_tokens: int = 10000
    budget_usd: float = 0.0


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

    api_key = settings.ai_api_key or None
    if not api_key and "openrouter.ai" in base_url:
        api_key = settings.openrouter_api_key or None

    if settings.ai_modes:
        modes = settings.ai_modes.split(",")
    else:
        modes = yaml_ai.get("modes") or ["review", "triage", "discovery"]
    triage = yaml_ai.get("triage") or {}
    discovery = yaml_ai.get("discovery") or {}

    def _int(value, default):
        return int(value) if value is not None else default

    return AiSettings(
        enabled=yaml_enabled,
        provider=str(yaml_ai.get("provider") or "openai_compatible"),
        base_url=base_url.rstrip("/"),
        model=model,
        api_key=api_key,
        timeout_seconds=int(yaml_ai.get("timeout_seconds") or 120),
        max_files=int(yaml_ai.get("max_files") or 25),
        max_file_bytes=int(yaml_ai.get("max_file_bytes") or 40000),
        max_findings=int(yaml_ai.get("max_findings") or 50),
        modes=tuple(m.strip() for m in modes if str(m).strip()),
        requests_per_minute=yaml_ai.get("requests_per_minute"),
        requests_per_day=yaml_ai.get("requests_per_day"),
        max_concurrency=_int(yaml_ai.get("max_concurrency"), 1),
        reasoning_headroom=_int(yaml_ai.get("reasoning_headroom"), 0),
        params=dict(yaml_ai.get("params") or {}),
        triage_max_findings=_int(triage.get("max_findings"), 10),
        triage_per_prompt=_int(triage.get("per_prompt"), 5),
        triage_budget_tokens=_int(triage.get("budget_tokens"), 6000),
        discovery_n_base=_int(discovery.get("n_base"), 6),
        discovery_n_cap=_int(discovery.get("n_cap"), 12),
        discovery_per_prompt=_int(discovery.get("per_prompt"), 5),
        discovery_budget_tokens=_int(discovery.get("budget_tokens"), 10000),
        budget_usd=float(yaml_ai.get("budget_usd") or 0.0),
    )


def is_ai_enabled(enable_override: bool | None = None) -> bool:
    """Active only when config says on (or per-scan override) and API key exists."""
    cfg = load_ai_settings()
    if enable_override is False:
        return False
    want = cfg.enabled if enable_override is None else True
    return want and bool(cfg.api_key)
