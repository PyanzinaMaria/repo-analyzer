from __future__ import annotations

import json
import logging
import subprocess
import sys
import uuid
from pathlib import Path

from app.models.finding import Finding, Severity

logger = logging.getLogger(__name__)


def _pick_requirements(root: Path) -> Path | None:
    for name in ("requirements.txt", "requirements-dev.txt"):
        candidate = root / name
        if candidate.exists():
            return candidate
    return None


def run_pip_audit(root: Path) -> list[Finding]:
    req = _pick_requirements(root)
    if req is None:
        logger.info("No requirements.txt for pip-audit in %s", root)
        return []

    cmd = [
        sys.executable,
        "-m",
        "pip_audit",
        "-r",
        str(req),
        "-f",
        "json",
        "--progress-spinner",
        "off",
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
        logger.warning("pip-audit failed to start: %s", exc)
        return []

    raw = proc.stdout.strip()
    if not raw:
        if proc.returncode not in (0, 1):
            logger.warning("pip-audit error: %s", proc.stderr[-1000:])
        return []

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("pip-audit returned non-JSON output")
        return []

    # pip-audit JSON may be a list of deps or {"dependencies": [...]}
    deps = payload if isinstance(payload, list) else payload.get("dependencies", [])
    findings: list[Finding] = []
    for dep in deps:
        name = dep.get("name") or "unknown"
        version = dep.get("version") or "?"
        for vuln in dep.get("vulns", []) or []:
            aliases = vuln.get("aliases") or []
            cve = next((a for a in aliases if str(a).startswith("CVE-")), None)
            findings.append(
                Finding(
                    id=f"pipaudit-{uuid.uuid4().hex[:10]}",
                    title=f"Vulnerable dependency: {name}=={version}",
                    description=vuln.get("description")
                    or f"Known vulnerability in {name} {version}",
                    severity=Severity.high,
                    cwe=None,
                    file=req.relative_to(root).as_posix(),
                    line=None,
                    rule_id=vuln.get("id") or cve,
                    source="pip-audit",
                    language="python",
                    remediation=(
                        f"Обновите пакет {name} до безопасной версии. "
                        f"Fix versions: {vuln.get('fix_versions')}"
                    ),
                    extra={
                        "package": name,
                        "version": version,
                        "aliases": aliases,
                        "fix_versions": vuln.get("fix_versions"),
                    },
                )
            )
    return findings
