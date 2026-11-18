from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.languages.base import LanguageHandler
from app.languages.python.inventory import build_inventory, iter_python_files
from app.languages.python.runnable import detect_python_runnable
from app.languages.python.scanners import run_bandit, run_pip_audit
from app.models.finding import Finding, LanguageAnalysis, Severity
from app.sandbox.models import RunPlan

logger = logging.getLogger(__name__)

_PYTHON_HINTS = ("fastapi", "uvicorn", "flask", "django", "werkzeug")


class PythonHandler(LanguageHandler):
    id = "python"
    display_name = "Python"
    extensions = (".py",)

    def detect(self, root: Path) -> bool:
        return bool(iter_python_files(root))

    def analyze(self, root: Path, job_ctx: dict[str, Any] | None = None) -> LanguageAnalysis:
        logger.info("Python analysis started for %s", root)
        findings = []
        findings.extend(run_bandit(root))
        findings.extend(run_pip_audit(root))
        inventory = build_inventory(root)
        return LanguageAnalysis(
            language=self.id,
            findings=findings,
            inventory=inventory,
            meta={
                "scanners": ["bandit", "pip-audit"],
                "files_scanned": inventory.files_count,
                "job_ctx": job_ctx or {},
            },
        )

    def detect_runnable(self, root: Path) -> RunPlan | None:
        return detect_python_runnable(root, language_id=self.id)

    def detect_runtime(self, target_url: str, fingerprint: dict[str, Any]) -> bool:
        hints = {str(h).lower() for h in (fingerprint.get("hints") or [])}
        if hints.intersection(_PYTHON_HINTS):
            return True
        server = str(fingerprint.get("server") or "").lower()
        powered = str(fingerprint.get("powered_by") or "").lower()
        body = str(fingerprint.get("body_sample") or "").lower()
        blob = f"{server} {powered} {body}"
        return any(h in blob for h in _PYTHON_HINTS)

    def analyze_dast(
        self,
        target_url: str,
        job_ctx: dict[str, Any] | None = None,
    ) -> LanguageAnalysis:
        """Python-web dynamic checks: OpenAPI/docs exposure and debug traces."""
        findings: list[Finding] = []
        probed: list[str] = []
        base = target_url if target_url.endswith("/") else target_url + "/"
        paths = ("docs", "redoc", "openapi.json", "swagger")

        try:
            with httpx.Client(follow_redirects=True, timeout=10.0) as client:
                for path in paths:
                    url = urljoin(base, path)
                    probed.append(url)
                    try:
                        resp = client.get(url)
                    except httpx.HTTPError:
                        continue
                    if resp.status_code < 400:
                        findings.append(
                            Finding(
                                id=f"dast-python-docs-{uuid.uuid4().hex[:8]}",
                                title=f"Public API docs endpoint: /{path}",
                                description=(
                                    "Interactive API documentation or schema is publicly reachable. "
                                    "Confirm this is intentional for the environment."
                                ),
                                severity=Severity.info,
                                cwe="CWE-200",
                                rule_id=f"python-public-{path}",
                                source="dast-python",
                                language=self.id,
                                extra={
                                    "url": str(resp.url),
                                    "method": "GET",
                                    "evidence": f"status={resp.status_code}",
                                },
                            )
                        )

                # Django-ish debug fingerprint on a nonsense path
                debug_url = urljoin(base, "dast-probe-" + uuid.uuid4().hex[:6])
                try:
                    debug_resp = client.get(debug_url)
                    body = (debug_resp.text or "").lower()
                    if "django" in body and ("traceback" in body or "disallowedhost" in body or "debug" in body):
                        findings.append(
                            Finding(
                                id=f"dast-python-debug-{uuid.uuid4().hex[:8]}",
                                title="Possible Django debug / verbose error page",
                                description="Error response appears to expose Django debug details.",
                                severity=Severity.high,
                                cwe="CWE-215",
                                rule_id="python-django-debug",
                                source="dast-python",
                                language=self.id,
                                extra={
                                    "url": str(debug_resp.url),
                                    "method": "GET",
                                    "evidence": "django debug markers in body",
                                },
                            )
                        )
                except httpx.HTTPError:
                    pass
        except httpx.HTTPError as exc:
            logger.warning("Python analyze_dast transport error for %s: %s", target_url, exc)
            return LanguageAnalysis(
                language=self.id,
                findings=[],
                meta={"dast": "error", "error": str(exc), "probed": probed},
            )

        return LanguageAnalysis(
            language=self.id,
            findings=findings,
            meta={
                "dast": "ok",
                "probed": probed,
                "host": urlparse(target_url).hostname,
                "job_ctx_keys": sorted((job_ctx or {}).keys()),
            },
        )
