from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.core.config import get_settings, load_yaml_settings


@dataclass(frozen=True)
class SandboxConfig:
    enabled: bool = True
    boot_timeout_seconds: int = 90
    memory: str = "512m"
    cpus: str = "1.0"
    network: str = "repo-analyzer-dast"
    base_image: str = "python:3.11-slim"
    publish_host: str = "127.0.0.1"


def get_sandbox_config() -> SandboxConfig:
    settings = get_settings()
    yaml_cfg = load_yaml_settings(settings.settings_path)
    raw: dict[str, Any] = dict(yaml_cfg.get("sandbox") or {})
    return SandboxConfig(
        enabled=bool(raw.get("enabled", True)),
        boot_timeout_seconds=int(raw.get("boot_timeout_seconds", 90)),
        memory=str(raw.get("memory", "512m")),
        cpus=str(raw.get("cpus", "1.0")),
        network=str(raw.get("network", "repo-analyzer-dast")),
        base_image=str(raw.get("base_image", "python:3.11-slim")),
        publish_host=str(raw.get("publish_host", "127.0.0.1")),
    )
