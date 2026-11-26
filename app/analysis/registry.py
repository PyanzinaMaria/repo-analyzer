"""Analysis runner registry: what a scan may request.

Mirrors ``app/languages/registry.py``: the catalog (what exists in code) is
here, while availability (what this deployment offers) lives in config —
``config/settings.yaml`` lists enabled runner keys under ``methods:``. The
frontend's method ids (sast, llm_agentic, ...) are mapped to runner keys by
the worker via frontend/config/analysis.yaml; this module only knows runner
keys.
"""

from __future__ import annotations

from app.core.config import get_settings, load_yaml_settings

RUNNER_STATIC = "static"
RUNNER_AI = "ai"

# Runner keys that exist as concepts. `dynamic` runs sandbox + DAST after
# SAST; `manual` (UI «Пентест») runs the security pipeline + active agent.
KNOWN_RUNNERS = (RUNNER_STATIC, RUNNER_AI, "dynamic", "manual")

# Runners used when a scan does not request any (legacy jobs): the static
# loop always runs, AI follows the config/per-scan override.
DEFAULT_RUNNERS = (RUNNER_STATIC,)


def enabled_runners() -> tuple[str, ...]:
    settings = get_settings()
    raw = load_yaml_settings(settings.settings_path)
    methods = raw.get("methods")
    if not isinstance(methods, list) or not methods:
        return DEFAULT_RUNNERS + (RUNNER_AI,)
    return tuple(str(m) for m in methods)


def check_runners(requested: list[str] | None) -> None:
    """Fail fast on unknown or deployment-disabled runner keys."""
    if requested is None:
        return
    enabled = set(enabled_runners())
    for runner in requested:
        if runner not in KNOWN_RUNNERS:
            raise ValueError(f"unknown analysis runner: {runner!r}")
        if runner not in enabled:
            raise ValueError(f"analysis runner disabled in this deployment: {runner!r}")


def compose_scan_kind(
    runners: list[str] | None,
    *,
    legacy_kind: str | None = None,
) -> str:
    """Build summary ``scan_kind`` from runner keys (static/ai/dynamic/manual).

    Form jobs always pass ``runners``; legacy jobs (``None``) keep
    ``legacy_kind`` (typically ``sast`` or ``sast+dast`` after sandbox).
    """
    if runners is None:
        return legacy_kind or "sast"

    parts: list[str] = []
    if "static" in runners:
        parts.append("sast")
    if "ai" in runners:
        parts.append("ai")
    if "dynamic" in runners:
        parts.append("dast")
    if "manual" in runners:
        parts.append("pentest")

    if not parts:
        return "sast"
    # Historical label when only the AI runner (optionally with static) ran.
    if parts == ["ai"] or parts == ["sast", "ai"]:
        return "sast_ai"
    return "+".join(parts)
