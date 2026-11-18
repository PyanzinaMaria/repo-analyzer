from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


StartMethod = Literal["dockerfile", "compose", "heuristic"]


@dataclass
class RunPlan:
    """How to boot a web target inside the Docker sandbox."""

    method: StartMethod
    context_dir: Path
    port: int = 8000
    health_path: str = "/"
    language: str = "http"
    # dockerfile: path relative to context_dir, or absolute generated file
    dockerfile: Path | None = None
    # compose: path to compose file
    compose_file: Path | None = None
    compose_service: str | None = None
    # heuristic metadata
    framework: str | None = None
    entry: str | None = None
    cmd: list[str] = field(default_factory=list)
    requirements_file: str | None = None
    image_tag: str | None = None


@dataclass
class SandboxSession:
    """Live sandbox instance returned by the runner."""

    container_name: str
    network: str
    # URL reachable from the host (published port)
    host_url: str
    # URL reachable from other containers on the sandbox network
    network_url: str
    plan: RunPlan
    meta: dict = field(default_factory=dict)
