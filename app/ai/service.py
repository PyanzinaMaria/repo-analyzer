from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import httpx

from app.ai.client import AiClientError, OpenAICompatibleClient
from app.ai.config import AiSettings, load_ai_settings
from app.ai.parser import parse_ai_findings
from app.ai.prompts import build_user_prompt
from app.ai.selector import select_files
from app.models.finding import CodeInventory, Finding

logger = logging.getLogger(__name__)


def _meta(
    *,
    enabled: bool,
    status: str,
    model: str | None = None,
    files_sent: int = 0,
    findings_count: int = 0,
    error: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "enabled": enabled,
        "status": status,
        "model": model,
        "files_sent": files_sent,
        "findings_count": findings_count,
        "error": error,
    }
    if extra:
        payload.update(extra)
    return payload


def _wants_ai(cfg: AiSettings, enable_override: bool | None) -> tuple[bool, str | None]:
    if enable_override is False:
        return False, "disabled_by_request"
    want = True if enable_override is True else cfg.enabled
    if not want:
        return False, "disabled_in_config"
    if not cfg.api_key:
        return False, "missing_api_key"
    return True, None


def run_ai_analysis(
    root: Path,
    findings: list[Finding],
    inventories: list[CodeInventory],
    *,
    enable_override: bool | None = None,
    transport: httpx.BaseTransport | None = None,
    settings: AiSettings | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    """Post-scan LLM review. Soft-fail: never raises to the scan orchestrator."""
    cfg = settings or load_ai_settings()
    want, skip_reason = _wants_ai(cfg, enable_override)
    if not want:
        return [], _meta(
            enabled=False,
            status="skipped",
            model=cfg.model,
            error=skip_reason,
        )

    try:
        selected = select_files(root, inventories, cfg)
        if not selected:
            return [], _meta(
                enabled=True,
                status="skipped",
                model=cfg.model,
                error="no_files_selected",
            )

        user_prompt = build_user_prompt(
            selected, findings, inventories, max_findings=cfg.max_findings
        )
        client = OpenAICompatibleClient(cfg, transport=transport)
        raw = client.chat_json(user_prompt)
        selected_paths = {item.rel_path for item in selected}

        try:
            ai_findings = parse_ai_findings(
                raw,
                selected_paths=selected_paths,
                existing_findings=findings,
                max_findings=cfg.max_findings,
            )
        except (ValueError, json.JSONDecodeError) as parse_exc:
            logger.warning("AI JSON parse failed, retrying once: %s", parse_exc)
            raw = client.chat_json(user_prompt, repair=True)
            ai_findings = parse_ai_findings(
                raw,
                selected_paths=selected_paths,
                existing_findings=findings,
                max_findings=cfg.max_findings,
            )

        return ai_findings, _meta(
            enabled=True,
            status="completed",
            model=cfg.model,
            files_sent=len(selected),
            findings_count=len(ai_findings),
            extra={"provider": cfg.provider},
        )
    except AiClientError as exc:
        logger.warning("AI analysis failed (client): %s", exc)
        return [], _meta(
            enabled=True,
            status="failed",
            model=cfg.model,
            error=str(exc),
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("AI analysis failed")
        return [], _meta(
            enabled=True,
            status="failed",
            model=cfg.model,
            error=str(exc),
        )
