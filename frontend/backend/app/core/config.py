"""Configuration layer.

Every runtime value comes from YAML files under ``config/`` and ``i18n/``.
Environment variables (SIRIUS_*) override selected values; nothing is
hardcoded anywhere else in the application.
"""

from __future__ import annotations

import fnmatch
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class AppConfig(BaseModel):
    title: str
    base_url: str
    data_dir: Path
    uploads_dir_name: str = "uploads"
    reports_dir_name: str = "reports"
    queue_dir_name: str = "queue"
    queue_driver: str = "filesystem"
    retention_days: int = 14
    server: ServerConfig


class ServerConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8000
    max_body_bytes: int = 50 * 1024 * 1024


class UploadConfig(BaseModel):
    max_upload_bytes: int
    max_unpacked_bytes: int
    max_file_bytes: int
    max_files: int
    max_depth: int
    compression_ratio_max: int
    timeout_seconds: int
    deny_hidden: bool = True
    forbidden_segments: list[str] = Field(default_factory=list)
    allowed_extensions: list[str] = Field(default_factory=list)
    manifest_patterns: list[str] = Field(default_factory=list)

    def entry_allowed(self, name: str) -> bool:
        """Decide by file name: extension whitelist or manifest pattern."""
        lowered = name.lower()
        if any(lowered.endswith(ext) for ext in self.allowed_extensions):
            return True
        basename = Path(name).name
        return any(fnmatch.fnmatch(basename, pat) for pat in self.manifest_patterns)


class ArtifactSpec(BaseModel):
    name: str
    label_key: str
    media_type: str
    viewer: str = "none"
    download: bool = False


class ReportsConfig(BaseModel):
    manifest_filename: str = "manifest.json"
    summary_filename: str = "summary.json"
    artifacts: list[ArtifactSpec]
    stages: list[str]

    def artifact(self, name: str) -> ArtifactSpec | None:
        return next((a for a in self.artifacts if a.name == name), None)


class VisibleWhen(BaseModel):
    field: str
    equals: str


class FieldValidators(BaseModel):
    max_length: int | None = None
    max_files: int | None = None
    allowed_hosts: list[str] | None = None


class FieldSpec(BaseModel):
    name: str
    type: str
    label_key: str
    required: bool = False
    default: str | None = None
    placeholder_key: str | None = None
    help_key: str | None = None
    group: str | None = None
    choices: list[dict[str, str]] = Field(default_factory=list)
    visible_when: VisibleWhen | None = None
    validators: FieldValidators = FieldValidators()


class FormSpec(BaseModel):
    id: str
    title_key: str
    submit_label_key: str
    fields: list[FieldSpec]


class ThemeConfig(BaseModel):
    colors: dict[str, str]
    font: dict[str, str]
    shape: dict[str, str]
    severity_colors: dict[str, str] = Field(default_factory=dict)

    def color(self, token: str) -> str:
        return self.colors.get(token, "#888888")


class Paths(BaseModel):
    """Resolved runtime directories derived from app config."""

    uploads: Path
    reports: Path
    queue: Path


class Settings(BaseModel):
    app: AppConfig
    upload: UploadConfig
    reports: ReportsConfig
    theme: ThemeConfig
    forms: dict[str, FormSpec]
    i18n: dict[str, Any]
    root: Path

    @property
    def paths(self) -> Paths:
        data = self.app.data_dir
        return Paths(
            uploads=data / self.app.uploads_dir_name,
            reports=data / self.app.reports_dir_name,
            queue=data / self.app.queue_dir_name,
        )

    def translate(self, key: str, **kwargs: Any) -> str:
        """Resolve a dotted i18n key; returns the key itself when missing."""
        node: Any = self.i18n
        for part in key.split("."):
            if not isinstance(node, dict) or part not in node:
                return key
            node = node[part]
        if isinstance(node, str):
            return node.format(**kwargs) if kwargs else node
        return key


def _read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _find_root() -> Path:
    env = os.environ.get("SIRIUS_APP_ROOT")
    if env:
        return Path(env).resolve()
    # backend/app/core/config.py -> repo root
    return Path(__file__).resolve().parents[3]


def _load_forms(forms_dir: Path) -> dict[str, FormSpec]:
    forms: dict[str, FormSpec] = {}
    for path in sorted(forms_dir.glob("*.yaml")):
        spec = FormSpec.model_validate(_read_yaml(path))
        forms[spec.id] = spec
    return forms


def _apply_env(settings: Settings) -> Settings:
    """Apply SIRIUS_* environment overrides to loaded values."""
    app = settings.app.model_copy()
    if v := os.environ.get("SIRIUS_APP_TITLE"):
        app.title = v
    if v := os.environ.get("SIRIUS_BASE_URL"):
        app.base_url = v
    if v := os.environ.get("SIRIUS_DATA_DIR"):
        app.data_dir = Path(v)
    if v := os.environ.get("SIRIUS_MAX_BODY_BYTES"):
        app.server = app.server.model_copy(update={"max_body_bytes": int(v)})
    if (v := os.environ.get("SIRIUS_HOST")) or (v := os.environ.get("SIRIUS_PORT")):
        updates: dict[str, Any] = {}
        if os.environ.get("SIRIUS_HOST"):
            updates["host"] = v
        if os.environ.get("SIRIUS_PORT"):
            updates["port"] = int(v)
        app.server = app.server.model_copy(update=updates)
    return settings.model_copy(update={"app": app})


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    root = _find_root()
    app_raw = _read_yaml(root / "config" / "app.yaml")
    app_raw.setdefault("server", {})
    if (data_dir := app_raw.get("data_dir")) and not Path(data_dir).is_absolute():
        app_raw["data_dir"] = str(root / data_dir)
    app = AppConfig.model_validate(app_raw)

    upload = UploadConfig.model_validate(_read_yaml(root / "config" / "upload.yaml"))
    reports = ReportsConfig.model_validate(_read_yaml(root / "config" / "reports.yaml"))
    theme = ThemeConfig.model_validate(_read_yaml(root / "config" / "theme.yaml"))
    forms = _load_forms(root / "config" / "forms")
    i18n = _read_yaml(root / "i18n" / "ru.yaml")

    settings = Settings(
        app=app,
        upload=upload,
        reports=reports,
        theme=theme,
        forms=forms,
        i18n=i18n,
        root=root,
    )
    return _apply_env(settings)


def reload_settings() -> Settings:
    """Drop the cached settings (used by tests to switch config per case)."""
    get_settings.cache_clear()
    return get_settings()
