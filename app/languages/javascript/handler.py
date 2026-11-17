from __future__ import annotations

from pathlib import Path
from typing import Any

from app.languages.base import LanguageHandler
from app.models.finding import CodeInventory, LanguageAnalysis


class JavaScriptHandler(LanguageHandler):
    """Stub handler — disabled in MVP; enable via config/settings.yaml later."""

    id = "javascript"
    display_name = "JavaScript"
    extensions = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

    def detect(self, root: Path) -> bool:
        return any(root.rglob(f"*{ext}") for ext in self.extensions)

    def analyze(self, root: Path, job_ctx: dict[str, Any] | None = None) -> LanguageAnalysis:
        # Intentionally empty for MVP modularity demo.
        return LanguageAnalysis(
            language=self.id,
            findings=[],
            inventory=CodeInventory(language=self.id, files_count=0),
            meta={"status": "stub", "message": "JavaScript handler not implemented yet"},
        )
