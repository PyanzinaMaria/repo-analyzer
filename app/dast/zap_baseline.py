from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

from app.dast.config import DastConfig
from app.dast.normalize import normalize_zap_alerts
from app.models.finding import Finding

logger = logging.getLogger(__name__)


def _docker_reachable_url(target_url: str) -> str:
    """Rewrite localhost so a ZAP container can reach the host-published port."""
    parsed = urlparse(target_url)
    host = (parsed.hostname or "").lower()
    if host in {"127.0.0.1", "localhost", "::1"}:
        netloc = parsed.netloc.replace(parsed.hostname or host, "host.docker.internal", 1)
        return urlunparse(parsed._replace(netloc=netloc))
    return target_url


def _extract_alerts(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [a for a in payload if isinstance(a, dict)]
    if not isinstance(payload, dict):
        return []
    # Common ZAP JSON shapes
    if isinstance(payload.get("site"), list):
        alerts: list[dict[str, Any]] = []
        for site in payload["site"]:
            if isinstance(site, dict) and isinstance(site.get("alerts"), list):
                alerts.extend(a for a in site["alerts"] if isinstance(a, dict))
        return alerts
    if isinstance(payload.get("alerts"), list):
        return [a for a in payload["alerts"] if isinstance(a, dict)]
    return []


def run_zap_baseline(
    target_url: str,
    cfg: DastConfig,
    *,
    language: str = "http",
    work_dir: Path | None = None,
    docker_network: str | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    """Run OWASP ZAP baseline in Docker and normalize alerts.

    Soft-fails when Docker/ZAP is unavailable: returns empty findings and
    meta.status explaining the skip/failure without raising.

    When ``docker_network`` is set, ZAP joins that network and ``target_url``
    is used as-is (for container DNS names). Otherwise localhost targets are
    rewritten to ``host.docker.internal``.
    """
    meta: dict[str, Any] = {
        "engine": "zap_baseline",
        "image": cfg.zap_image,
        "status": "skipped",
    }
    docker = shutil.which("docker")
    if not docker:
        meta["reason"] = "docker not found on PATH"
        logger.warning("ZAP baseline skipped: %s", meta["reason"])
        return [], meta

    own_tmp = work_dir is None
    out_dir = work_dir or Path(tempfile.mkdtemp(prefix="dast-zap-"))
    out_dir.mkdir(parents=True, exist_ok=True)
    report_name = "zap-report.json"
    report_path = out_dir / report_name

    if docker_network:
        scan_url = target_url
    else:
        scan_url = _docker_reachable_url(target_url)
    meta["scan_url"] = scan_url
    meta["docker_network"] = docker_network
    cmd = [
        docker,
        "run",
        "--rm",
    ]
    if docker_network:
        cmd.extend(["--network", docker_network])
    else:
        cmd.append("--add-host=host.docker.internal:host-gateway")
    cmd.extend(
        [
            "-v",
            f"{out_dir.resolve()}:/zap/wrk:rw",
            cfg.zap_image,
            "zap-baseline.py",
            "-t",
            scan_url,
            "-J",
            report_name,
            "-I",  # do not return failure on warnings alone
        ]
    )
    meta["command"] = cmd
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=cfg.timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        meta["status"] = "failed"
        meta["reason"] = f"zap baseline timed out after {cfg.timeout_seconds}s"
        logger.error(meta["reason"])
        return [], meta
    except OSError as exc:
        meta["status"] = "failed"
        meta["reason"] = str(exc)
        logger.exception("ZAP baseline failed to start")
        return [], meta
    finally:
        if own_tmp:
            # keep report if present for debugging under temp; still readable below
            pass

    meta["exit_code"] = completed.returncode
    meta["stdout_tail"] = (completed.stdout or "")[-2000:]
    meta["stderr_tail"] = (completed.stderr or "")[-2000:]

    if not report_path.is_file():
        # ZAP may still exit 0/2 without JSON depending on image flags
        meta["status"] = "failed"
        meta["reason"] = "zap JSON report not produced"
        logger.warning("ZAP baseline produced no JSON for %s", target_url)
        return [], meta

    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        meta["status"] = "failed"
        meta["reason"] = f"invalid zap JSON: {exc}"
        return [], meta

    alerts = _extract_alerts(payload)
    findings = normalize_zap_alerts(alerts, language=language)
    meta["status"] = "ok"
    meta["alerts"] = len(alerts)
    meta["report_path"] = str(report_path)
    return findings, meta
