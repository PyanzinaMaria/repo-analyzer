from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.config import get_settings, load_yaml_settings
from app.models.report import ScanResult


def _env() -> Environment:
    settings = get_settings()
    return Environment(
        loader=FileSystemLoader(str(settings.templates_dir)),
        autoescape=select_autoescape(enabled_extensions=()),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def write_security_json(result: ScanResult, path: Path) -> Path:
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return path


def render_security_markdown(result: ScanResult, path: Path) -> Path:
    settings = get_settings()
    yaml_cfg = load_yaml_settings(settings.settings_path)
    disclaimer = yaml_cfg.get("reports", {}).get("disclaimer", "")
    template = _env().get_template("security_report.md.j2")
    content = template.render(result=result, disclaimer=disclaimer)
    path.write_text(content, encoding="utf-8")
    return path
