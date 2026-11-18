from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.core.config import get_settings, load_yaml_settings


@dataclass(frozen=True)
class DastConfig:
    enabled: bool = True
    engine: str = "zap_baseline"
    zap_image: str = "ghcr.io/zaproxy/zaproxy:stable"
    timeout_seconds: int = 300
    allowed_schemes: tuple[str, ...] = ("http", "https")
    allow_private_targets: bool = False


def get_dast_config() -> DastConfig:
    settings = get_settings()
    yaml_cfg = load_yaml_settings(settings.settings_path)
    raw: dict[str, Any] = dict(yaml_cfg.get("dast") or {})
    schemes = raw.get("allowed_schemes") or ["http", "https"]
    return DastConfig(
        enabled=bool(raw.get("enabled", True)),
        engine=str(raw.get("engine", "zap_baseline")),
        zap_image=str(raw.get("zap_image", "ghcr.io/zaproxy/zaproxy:stable")),
        timeout_seconds=int(raw.get("timeout_seconds", 300)),
        allowed_schemes=tuple(str(s).lower() for s in schemes),
        allow_private_targets=bool(raw.get("allow_private_targets", False)),
    )
