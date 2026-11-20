from __future__ import annotations

import os
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
    # IP the sandbox target's port is published on (docker -p bind, daemon
    # host side). Loopback keeps the target private for a host-run worker.
    publish_host: str = "127.0.0.1"
    # Host the published port is reachable on *from the worker process* —
    # it goes into readiness/preflight URLs. Equal to publish_host for a
    # host-run worker; a containerized worker overrides both:
    # SANDBOX_PUBLISH_BIND=0.0.0.0 (loopback bind is unreachable via
    # host.docker.internal) and SANDBOX_CONNECT_HOST=host.docker.internal.
    connect_host: str = "127.0.0.1"


def get_sandbox_config() -> SandboxConfig:
    settings = get_settings()
    yaml_cfg = load_yaml_settings(settings.settings_path)
    raw: dict[str, Any] = dict(yaml_cfg.get("sandbox") or {})
    publish_host = os.environ.get(
        "SANDBOX_PUBLISH_BIND", str(raw.get("publish_host", "127.0.0.1"))
    ).strip() or "0.0.0.0"
    connect_host = os.environ.get(
        "SANDBOX_CONNECT_HOST", str(raw.get("connect_host", publish_host))
    ).strip() or publish_host
    return SandboxConfig(
        enabled=bool(raw.get("enabled", True)),
        boot_timeout_seconds=int(raw.get("boot_timeout_seconds", 90)),
        memory=str(raw.get("memory", "512m")),
        cpus=str(raw.get("cpus", "1.0")),
        network=str(raw.get("network", "repo-analyzer-dast")),
        base_image=str(raw.get("base_image", "python:3.11-slim")),
        publish_host=publish_host,
        connect_host=connect_host,
    )
