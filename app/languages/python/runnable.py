from __future__ import annotations

import re
from pathlib import Path

from app.sandbox.models import RunPlan

_EXCLUDE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    ".mypy_cache",
    ".ruff_cache",
}

_FRAMEWORK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("fastapi", re.compile(r"\bFastAPI\s*\(")),
    ("flask", re.compile(r"\bFlask\s*\(")),
    ("django", re.compile(r"\bdjango\b", re.I)),
]


def _iter_py_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*.py"):
        if any(part in _EXCLUDE_DIRS for part in path.parts):
            continue
        files.append(path)
    return files


def _find_requirements(root: Path) -> str | None:
    for name in ("requirements.txt", "requirements-dev.txt", "req.txt"):
        if (root / name).is_file():
            return name
    return None


def _module_from_path(root: Path, path: Path) -> str:
    rel = path.relative_to(root).with_suffix("")
    return ".".join(rel.parts)


def detect_python_runnable(root: Path, *, language_id: str = "python") -> RunPlan | None:
    """Heuristic RunPlan for Flask / FastAPI / Django web apps."""
    root = root.resolve()
    req = _find_requirements(root)
    py_files = _iter_py_files(root)
    if not py_files:
        return None

    # Prefer well-known entry filenames
    preferred = []
    others = []
    for path in py_files:
        name = path.name.lower()
        if name in {"app.py", "main.py", "wsgi.py", "asgi.py", "manage.py"}:
            preferred.append(path)
        else:
            others.append(path)

    candidates = preferred + others
    framework: str | None = None
    entry_path: Path | None = None
    app_var = "app"

    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for fw, pattern in _FRAMEWORK_PATTERNS:
            if not pattern.search(text):
                continue
            framework = fw
            entry_path = path
            # FastAPI/Flask usually bind `app = FastAPI()` / `app = Flask(...)`
            m = re.search(r"^(\w+)\s*=\s*(?:FastAPI|Flask)\s*\(", text, re.M)
            if m:
                app_var = m.group(1)
            break
        if framework:
            break

    if framework is None or entry_path is None:
        return None

    port = 8000
    health = "/"
    cmd: list[str]

    if framework == "django":
        # manage.py runserver
        manage = root / "manage.py"
        if not manage.is_file():
            return None
        port = 8000
        cmd = ["python", "manage.py", "runserver", f"0.0.0.0:{port}"]
        entry = "manage.py"
    elif framework == "flask":
        port = 5000
        module = _module_from_path(root, entry_path)
        # flask --app module:var run
        cmd = [
            "python",
            "-c",
            (
                f"from {module} import {app_var}; "
                f"{app_var}.run(host='0.0.0.0', port={port}, debug=False)"
            ),
        ]
        # Prefer executing the file if it has __main__
        try:
            text = entry_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            text = ""
        if '__name__' in text and "__main__" in text:
            cmd = ["python", str(entry_path.relative_to(root)).replace("\\", "/")]
        entry = str(entry_path.relative_to(root)).replace("\\", "/")
        health = "/login" if "login" in text.lower() or (root / "templates").exists() else "/"
    else:  # fastapi
        port = 8000
        module = _module_from_path(root, entry_path)
        cmd = [
            "uvicorn",
            f"{module}:{app_var}",
            "--host",
            "0.0.0.0",
            "--port",
            str(port),
        ]
        entry = f"{module}:{app_var}"
        health = "/docs"

    return RunPlan(
        method="heuristic",
        context_dir=root,
        port=port,
        health_path=health,
        language=language_id,
        framework=framework,
        entry=entry,
        cmd=cmd,
        requirements_file=req,
    )
