from __future__ import annotations

import logging
from pathlib import Path

from app.languages.registry import LanguageRegistry, build_registry
from app.sandbox.models import RunPlan

logger = logging.getLogger(__name__)


def detect_run_plan(
    root: Path,
    registry: LanguageRegistry | None = None,
) -> RunPlan | None:
    """Resolve how to boot a web target: compose → Dockerfile → language heuristics."""
    root = root.resolve()
    reg = registry or build_registry()

    for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        compose = root / name
        if compose.is_file():
            logger.info("Sandbox detect: compose file %s", compose)
            return RunPlan(
                method="compose",
                context_dir=root,
                compose_file=compose,
                port=8000,
                health_path="/",
                language="http",
            )

    for name in ("Dockerfile", "dockerfile"):
        dockerfile = root / name
        if dockerfile.is_file():
            logger.info("Sandbox detect: Dockerfile %s", dockerfile)
            return RunPlan(
                method="dockerfile",
                context_dir=root,
                dockerfile=dockerfile,
                port=8000,
                health_path="/",
                language="http",
            )

    for handler in reg.enabled():
        try:
            plan = handler.detect_runnable(root)
        except Exception:  # noqa: BLE001
            logger.exception("detect_runnable failed for %s", handler.id)
            continue
        if plan is not None:
            logger.info(
                "Sandbox detect: heuristic language=%s framework=%s entry=%s",
                handler.id,
                plan.framework,
                plan.entry,
            )
            return plan

    logger.info("Sandbox detect: no runnable web target in %s", root)
    return None
