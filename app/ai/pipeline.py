"""LLM stage of a scan: triage of SAST findings and vulnerability discovery (secaudit modes).

Runs after the language handlers, on their static-stage output (merged SAST findings + code context).
Configured by the `ai` section of config/settings.yaml (`modes`, rate limits, budgets) and the AI_* env vars;
answers are cached in <data>/llm_cache/cache.sqlite, so re-scanning the same code costs nothing.
Soft-fail: quota or provider errors are recorded in meta and the scan completes with what it has.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from app.ai.config import AiSettings
from app.ai.discovery import discover_functions
from app.ai.llm import BudgetExceeded, DailyLimitReached, LLMClient, UpstreamUnavailable
from app.ai.triage import triage_findings
from app.context.build import load_context
from app.core.runlog import RunSummary
from app.core.yaml_configs import BackendSpec, ModelsConfig, ModelSpec
from app.sast.engine import LanguageRun

logger = logging.getLogger(__name__)

LLM_MODES = ("triage", "discovery")


def build_client(cfg: AiSettings, data_root: Path) -> LLMClient:
    """LLMClient for the configured OpenAI-compatible endpoint. OpenRouter is named 'openrouter' so that the
    client can read model pricing and supported parameters from its catalog."""
    backend = "openrouter" if "openrouter.ai" in cfg.base_url else "ai"
    models = ModelsConfig(
        budget_usd=cfg.budget_usd,
        backends={backend: BackendSpec(base_url=cfg.base_url, api_key_env="AI_API_KEY", api_key=cfg.api_key,
                                       max_concurrency=cfg.max_concurrency,
                                       requests_per_minute=cfg.requests_per_minute,
                                       requests_per_day=cfg.requests_per_day)},
        models=[ModelSpec(id=cfg.model, backend=backend, params=cfg.params,
                          reasoning_headroom=cfg.reasoning_headroom)],
    )
    return LLMClient(models, mode="live", data_root=data_root)


def wanted_modes(cfg: AiSettings, enable_override: bool | None) -> tuple[list[str], str | None]:
    if enable_override is False:
        return [], "disabled_by_request"
    if not (enable_override is True or cfg.enabled):
        return [], "disabled_in_config"
    modes = [m for m in cfg.modes if m in LLM_MODES]
    if not modes:
        return [], "no_llm_modes"
    if not cfg.api_key and "localhost" not in cfg.base_url and "127.0.0.1" not in cfg.base_url:
        return [], "missing_api_key"
    return modes, None


def run_llm_stage(cfg: AiSettings, root: Path, runs: list[LanguageRun], data_root: Path, *,
                  enable_override: bool | None = None,
                  client: LLMClient | None = None) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """-> ({language: {"triage": rows | None, "discovery": rows | None}}, meta)."""
    modes, skip = wanted_modes(cfg, enable_override)
    meta: dict[str, Any] = {"enabled": bool(modes), "status": "skipped" if skip else "completed",
                            "model": cfg.model, "modes": modes, "error": skip, "errors": []}
    results: dict[str, dict[str, Any]] = {}
    if skip:
        return results, meta
    summary = RunSummary("llm")
    client = client or build_client(cfg, data_root)
    stop: str | None = None
    for run in runs:
        out: dict[str, Any] = {"triage": None, "discovery": None}
        results[run.language] = out
        if not (run.context_dir / "index.json").exists():
            meta["errors"].append(f"{run.language}: no code context, LLM stage skipped")
            continue
        snap = load_context(root, run.context_dir)
        for mode in modes:
            if stop:
                break
            try:
                if mode == "triage" and run.merged:
                    out["triage"] = triage_findings(
                        client, cfg.model, snap, run.language, run.merged[:cfg.triage_max_findings],
                        cfg.triage_budget_tokens, cfg.triage_per_prompt, summary, tag=f"triage:{root.name}")
                elif mode == "discovery":
                    out["discovery"] = discover_functions(
                        client, cfg.model, snap, run.language, run.loc, run.merged, cfg.discovery_n_base,
                        cfg.discovery_n_cap, cfg.discovery_per_prompt, cfg.discovery_budget_tokens, summary,
                        tag=f"discover:{root.name}")
            except (DailyLimitReached, BudgetExceeded, UpstreamUnavailable) as exc:
                stop = f"{type(exc).__name__}: {exc}"[:300]
                logger.warning("LLM stage stopped: %s", stop)
            except Exception as exc:  # noqa: BLE001 - never fail the scan because of the LLM
                logger.exception("LLM %s failed for %s", mode, run.language)
                meta["errors"].append(f"{run.language} {mode}: {exc}"[:300])
    meta["answers"] = dict(summary.counts)   # triage: ok/invalid per finding + calls; discovery: ok per call
    meta["cost_usd"] = round(summary.cost_usd, 6)
    if stop:
        meta["status"] = "partial"
        meta["error"] = stop
    elif meta["errors"] and not any(v["triage"] or v["discovery"] for v in results.values()):
        meta["status"] = "failed"
    return results, meta
