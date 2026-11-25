from __future__ import annotations

import os
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
    # Shared directory ZAP writes its JSON report into. Empty -> a temp dir
    # (works when the worker runs on the daemon host). A containerized worker
    # points it at a named volume also mounted into the ZAP container, or the
    # sibling container's volume mount would be invisible to the worker.
    work_dir: str = ""
    # Daemon-side name of that named volume. When set, ZAP is started with
    # --mount type=volume (volume-subpath per scan) instead of a -v path,
    # because a -v path from a containerized worker resolves on the daemon
    # host filesystem, not inside the worker container.
    docker_volume: str = ""
    # Passive ZAP baseline can be disabled when the image is not available;
    # the active pentest agent below does not need it.
    zap_enabled: bool = True
    # Active pentest agent on top of the passive baseline.
    pentest_enabled: bool = True
    pentest_use_llm: bool = True
    pentest_max_steps: int = 12
    pentest_max_seconds: int = 120


def get_dast_config() -> DastConfig:
    settings = get_settings()
    yaml_cfg = load_yaml_settings(settings.settings_path)
    raw: dict[str, Any] = dict(yaml_cfg.get("dast") or {})
    pentest = dict(raw.get("pentest") or {})
    schemes = raw.get("allowed_schemes") or ["http", "https"]
    return DastConfig(
        enabled=bool(raw.get("enabled", True)),
        engine=str(raw.get("engine", "zap_baseline")),
        zap_image=str(raw.get("zap_image", "ghcr.io/zaproxy/zaproxy:stable")),
        timeout_seconds=int(raw.get("timeout_seconds", 300)),
        allowed_schemes=tuple(str(s).lower() for s in schemes),
        allow_private_targets=bool(raw.get("allow_private_targets", False)),
        work_dir=os.environ.get("ZAP_WORK_DIR", str(raw.get("work_dir", ""))).strip(),
        docker_volume=os.environ.get(
            "ZAP_DOCKER_VOLUME", str(raw.get("docker_volume", ""))
        ).strip(),
        zap_enabled=bool(raw.get("zap_enabled", True)),
        pentest_enabled=bool(pentest.get("enabled", True)),
        pentest_use_llm=bool(pentest.get("llm_enabled", True)),
        pentest_max_steps=int(pentest.get("max_steps", 12)),
        pentest_max_seconds=int(pentest.get("max_seconds", 120)),
    )
