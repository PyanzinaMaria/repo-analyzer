from __future__ import annotations

from pathlib import Path

from app.languages.python.runnable import detect_python_runnable
from app.sandbox.detect import detect_run_plan
from app.languages.python.handler import PythonHandler
from app.languages.registry import LanguageRegistry


def test_detect_flask_intrapanel_layout(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("Flask==0.12.4\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n\n"
        "@app.route('/')\ndef index():\n    return 'ok'\n\n"
        "if __name__ == '__main__':\n    app.run(host='0.0.0.0', port=5000)\n",
        encoding="utf-8",
    )
    plan = detect_python_runnable(tmp_path)
    assert plan is not None
    assert plan.method == "heuristic"
    assert plan.framework == "flask"
    assert plan.port == 5000
    assert plan.requirements_file == "requirements.txt"
    assert plan.cmd[0] == "python"


def test_detect_fastapi_heuristic(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n",
        encoding="utf-8",
    )
    plan = detect_python_runnable(tmp_path)
    assert plan is not None
    assert plan.framework == "fastapi"
    assert plan.port == 8000
    assert "uvicorn" in plan.cmd[0]


def test_detect_prefers_dockerfile(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM python:3.9-slim\nEXPOSE 8080\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n",
        encoding="utf-8",
    )
    registry = LanguageRegistry(handlers=[PythonHandler(enabled=True)])
    registry.get("python").enabled = True
    plan = detect_run_plan(tmp_path, registry=registry)
    assert plan is not None
    assert plan.method == "dockerfile"


def test_no_web_framework_returns_none(tmp_path: Path) -> None:
    (tmp_path / "util.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    assert detect_python_runnable(tmp_path) is None
