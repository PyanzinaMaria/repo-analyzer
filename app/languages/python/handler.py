from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from app.languages.base import LanguageHandler
from app.languages.python.inventory import build_inventory, iter_python_files
from app.languages.python.scanners import run_bandit, run_pip_audit
from app.models.finding import LanguageAnalysis

logger = logging.getLogger(__name__)


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
