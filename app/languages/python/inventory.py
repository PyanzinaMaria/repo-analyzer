from __future__ import annotations

import ast
import logging
from pathlib import Path

from app.core.config import get_settings, load_yaml_settings
from app.models.finding import CodeInventory

logger = logging.getLogger(__name__)

DEPENDENCY_FILES = (
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "Pipfile",
    "setup.py",
)


def _exclude_dirs() -> set[str]:
    settings = get_settings()
    cfg = load_yaml_settings(settings.settings_path)
    return set(cfg.get("scan", {}).get("exclude_dirs", []))


def iter_python_files(root: Path) -> list[Path]:
    excluded = _exclude_dirs()
    files: list[Path] = []
    for path in root.rglob("*.py"):
        if any(part in excluded for part in path.parts):
            continue
        files.append(path)
    return files


def build_inventory(root: Path) -> CodeInventory:
    modules: set[str] = set()
    classes: set[str] = set()
    functions: set[str] = set()
    imports: set[str] = set()
    py_files = iter_python_files(root)

    for path in py_files:
        rel = path.relative_to(root).as_posix()
        modules.add(rel)
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            logger.debug("Skip inventory parse for %s", rel)
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                classes.add(f"{rel}:{node.name}")
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                functions.add(f"{rel}:{node.name}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split(".")[0])

    dependency_files = [
        name for name in DEPENDENCY_FILES if (root / name).exists()
    ]

    return CodeInventory(
        language="python",
        files_count=len(py_files),
        modules=sorted(modules),
        classes=sorted(classes),
        functions=sorted(functions),
        imports=sorted(imports),
        dependency_files=dependency_files,
    )
