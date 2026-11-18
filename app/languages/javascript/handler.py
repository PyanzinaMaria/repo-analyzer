from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from app.core import io
from app.languages.base import LanguageHandler
from app.languages.sast_support import run_static_stage
from app.models.finding import CodeInventory, LanguageAnalysis
from app.sast.engine import detect_family_language

logger = logging.getLogger(__name__)

DEPENDENCY_FILES = ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml")


class JavaScriptHandler(LanguageHandler):
    """JavaScript / TypeScript: ESLint (eslint-plugin-security), Semgrep and CodeQL through the shared SAST
    engine; inventory from the tree-sitter code index."""

    id = "javascript"
    display_name = "JavaScript / TypeScript"
    extensions = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts")

    def detect(self, root: Path) -> bool:
        return detect_family_language(root, "javascript") is not None

    def analyze(self, root: Path, job_ctx: dict[str, Any] | None = None) -> LanguageAnalysis:
        language = detect_family_language(root, "javascript") or "javascript"
        logger.info("JavaScript analysis (%s) started for %s", language, root)
        findings, run = run_static_stage(root, language, job_ctx)
        return LanguageAnalysis(
            language=self.id,
            findings=findings,
            inventory=_inventory(root, run.context_dir),
            meta={
                "scanners": [t for t, s in run.tools.items() if s.get("ok")],
                "dialect": language,
                "files_scanned": run.context.get("files", 0),
                "secaudit": run.meta(),
                "job_ctx": {k: v for k, v in (job_ctx or {}).items() if k != "work_dir"},
            },
        )


def _inventory(root: Path, ctx_dir: Path) -> CodeInventory:
    inv = CodeInventory(language="javascript")
    inv.dependency_files = sorted(
        p.relative_to(root).as_posix() for name in DEPENDENCY_FILES for p in root.glob(f"**/{name}")
        if "node_modules" not in p.parts
    )[:50]
    index_path = ctx_dir / "index.json"
    if not index_path.exists():
        return inv
    idx = io.read_json(index_path)
    files = idx.get("files", {})
    inv.files_count = len(files)
    inv.modules = sorted(files)
    names = sorted({fn["name"] for fi in files.values() for fn in fi.get("functions", [])
                    if not fn["name"].startswith("<anonymous")})
    inv.classes = sorted({n.split(".")[0] for n in names if "." in n})
    inv.functions = names
    inv.imports = sorted({imp for fi in files.values() for imp in fi.get("imports", [])})[:500]
    return inv
