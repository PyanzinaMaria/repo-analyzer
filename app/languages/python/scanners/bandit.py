from __future__ import annotations

import json
import logging
import subprocess
import sys
import uuid
from pathlib import Path

from app.models.finding import Finding, Severity

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "UNDEFINED": Severity.unknown,
    "LOW": Severity.low,
    "MEDIUM": Severity.medium,
    "HIGH": Severity.high,
}


def run_bandit(root: Path) -> list[Finding]:
    cmd = [
        sys.executable,
        "-m",
        "bandit",
        "-r",
        str(root),
        "-f",
        "json",
        "-q",
        "-x",
        ",".join(
            [
                str(root / ".git"),
                str(root / ".venv"),
                str(root / "venv"),
                str(root / "node_modules"),
                str(root / "tests"),
            ]
        ),
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("Bandit failed to start: %s", exc)
        return []

    # Bandit exits 1 when findings exist — still parse stdout.
    raw = proc.stdout.strip()
    if not raw:
        if proc.returncode not in (0, 1):
            logger.warning("Bandit error: %s", proc.stderr[-1000:])
        return []

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Bandit returned non-JSON output")
        return []

    findings: list[Finding] = []
    for item in payload.get("results", []):
        filename = item.get("filename") or ""
        try:
            rel = Path(filename).resolve().relative_to(root.resolve()).as_posix()
        except Exception:  # noqa: BLE001
            rel = filename

        cwe_id = None
        cwe = item.get("issue_cwe") or {}
        if isinstance(cwe, dict):
            cwe_id = f"CWE-{cwe.get('id')}" if cwe.get("id") else None

        findings.append(
            Finding(
                id=f"bandit-{uuid.uuid4().hex[:10]}",
                title=item.get("test_name") or item.get("test_id") or "Bandit finding",
                description=item.get("issue_text") or "",
                severity=_SEVERITY_MAP.get(
                    str(item.get("issue_severity", "UNDEFINED")).upper(),
                    Severity.unknown,
                ),
                cwe=cwe_id,
                file=rel,
                line=item.get("line_number"),
                rule_id=item.get("test_id"),
                source="bandit",
                language="python",
                remediation="Исправьте опасный паттерн согласно рекомендации Bandit/CWE.",
                extra={
                    "confidence": item.get("issue_confidence"),
                    "more_info": item.get("more_info"),
                    "code": item.get("code"),
                },
            )
        )
    return findings
