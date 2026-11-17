from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from app.models.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Exact pin required for --no-deps --disable-pip (no temp venv install).
_PINNED_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*===?\s*([^\s;#]+)",
)


def _pick_requirements(root: Path) -> Path | None:
    for name in ("requirements.txt", "requirements-dev.txt"):
        candidate = root / name
        if candidate.exists():
            return candidate
    return None


def _split_requirement_lines(req: Path) -> tuple[list[str], list[str]]:
    """Return (pinned_lines, skipped_spec_lines)."""
    pinned: list[str] = []
    skipped: list[str] = []
    for raw in req.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            # -r / -e / --index-url etc. — not auditable without pip resolve
            skipped.append(line)
            continue
        if _PINNED_RE.match(line):
            pinned.append(line)
        else:
            skipped.append(line)
    return pinned, skipped


def _scanner_issue(
    req: Path,
    root: Path,
    title: str,
    description: str,
    severity: Severity = Severity.medium,
) -> Finding:
    try:
        file_ref = req.relative_to(root).as_posix()
    except ValueError:
        file_ref = req.name
    return Finding(
        id=f"pipaudit-{uuid.uuid4().hex[:10]}",
        title=title,
        description=description,
        severity=severity,
        cwe=None,
        file=file_ref,
        line=None,
        rule_id="pip-audit-error",
        source="pip-audit",
        language="python",
        remediation=(
            "Зафиксируйте зависимости точными версиями (pkg==x.y.z) "
            "или укажите lock-файл. Сканер использует pip-audit "
            "--no-deps --disable-pip, без установки пакетов в окружение."
        ),
        extra={},
    )


def run_pip_audit(root: Path) -> list[Finding]:
    req = _pick_requirements(root)
    if req is None:
        logger.info("No requirements.txt for pip-audit in %s", root)
        return []

    pinned, skipped = _split_requirement_lines(req)
    findings: list[Finding] = []

    if skipped:
        findings.append(
            _scanner_issue(
                req,
                root,
                "pip-audit: часть зависимостей пропущена (нет точного pin)",
                (
                    "Без установки пакетов во временный venv аудитятся только "
                    f"строки с ==/===. Пропущено ({len(skipped)}): "
                    + "; ".join(skipped[:20])
                    + ("…" if len(skipped) > 20 else "")
                ),
                severity=Severity.info,
            )
        )

    if not pinned:
        findings.append(
            _scanner_issue(
                req,
                root,
                "pip-audit: нет закреплённых зависимостей для SCA",
                (
                    f"В {req.name} нет строк вида package==version. "
                    "Установка пакетов во временный venv отключена намеренно "
                    "(ломается на новых Python / старых wheels)."
                ),
            )
        )
        return findings

    with tempfile.TemporaryDirectory(prefix="repo-analyzer-pip-audit-") as tmp:
        pinned_file = Path(tmp) / "pinned-requirements.txt"
        out_file = Path(tmp) / "pip_audit.json"
        pinned_file.write_text("\n".join(pinned) + "\n", encoding="utf-8")

        # --no-deps --disable-pip: query advisory DB without installing into a
        # temp venv (avoids build failures for old packages on new Python).
        cmd = [
            sys.executable,
            "-m",
            "pip_audit",
            "-r",
            str(pinned_file),
            "--no-deps",
            "--disable-pip",
            "-f",
            "json",
            "--progress-spinner",
            "off",
            "-o",
            str(out_file),
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
            findings.append(
                _scanner_issue(
                    req,
                    root,
                    "pip-audit: не удалось запустить",
                    str(exc),
                )
            )
            return findings

        # 0 = clean, 1 = vulnerabilities found (success for us).
        if proc.returncode not in (0, 1) or not out_file.exists():
            err = (proc.stderr or proc.stdout or "").strip()[-1500:]
            logger.warning("pip-audit error (code=%s): %s", proc.returncode, err)
            findings.append(
                _scanner_issue(
                    req,
                    root,
                    "pip-audit: сбой сканирования зависимостей",
                    err or f"exit code {proc.returncode}, empty output",
                )
            )
            return findings

        try:
            payload = json.loads(out_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            logger.warning("pip-audit returned non-JSON output")
            findings.append(
                _scanner_issue(
                    req,
                    root,
                    "pip-audit: некорректный JSON",
                    "Не удалось разобрать вывод pip-audit.",
                )
            )
            return findings

    deps = payload if isinstance(payload, list) else payload.get("dependencies", [])
    try:
        file_ref = req.relative_to(root).as_posix()
    except ValueError:
        file_ref = req.name

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
                    file=file_ref,
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
