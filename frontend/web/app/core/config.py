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
    document: str | None = None   # set on artifacts derived from documents x formats
    format: str | None = None


class FormatSpec(BaseModel):
    id: str
    media_type: str
    viewer: str = "none"
    download: bool = False


class DocumentSpec(BaseModel):
    id: str
    label_key: str
    formats: list[str]
    legacy_formats: list[str] = Field(default_factory=list)


class ReportsDefaults(BaseModel):
    formats: list[str] = Field(default_factory=list)


class ReportsConfig(BaseModel):
    manifest_filename: str = "manifest.json"
    summary_filename: str = "summary.json"
    formats: list[FormatSpec] = Field(default_factory=list)
    documents: list[DocumentSpec] = Field(default_factory=list)
    defaults: ReportsDefaults = Field(default_factory=ReportsDefaults)
    artifacts: list[ArtifactSpec] = Field(default_factory=list)
    stages: list[str] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        # The serveable artifact list is derived from documents x formats
        # ({document}.{format}); producers never see this, it only drives
        # serving, viewers and downloads.
        if not self.documents:
            return
        fmt = {f.id: f for f in self.formats}
        artifacts = []
        for doc in self.documents:
            for format_id in dict.fromkeys(doc.formats + doc.legacy_formats):
                spec = fmt.get(format_id)
                if spec is None:
                    raise ValueError(
                        f"reports.yaml: document {doc.id!r} references unknown format {format_id!r}"
                    )
                artifacts.append(ArtifactSpec(
                    name=f"{doc.id}.{format_id}",
                    label_key=doc.label_key,
                    media_type=spec.media_type,
                    viewer=spec.viewer,
                    download=spec.download,
                    document=doc.id,
                    format=format_id,
                ))
        self.artifacts = artifacts

    def artifact(self, name: str) -> ArtifactSpec | None:
        return next((a for a in self.artifacts if a.name == name), None)

    def format_choices(self) -> list[dict[str, str]]:
        """Formats offered for the FSTEC documentation."""
        fstec = next((doc for doc in self.documents if doc.id == "doc"), None)
        allowed = set(fstec.formats) if fstec else set()
        return [
            {"value": f.id, "label_key": f"formats.{f.id}.label"}
            for f in self.formats
            if f.id in allowed
        ]


class MethodSpec(BaseModel):
    id: str
    runner: str
    available: bool = True
    label_key: str
    description_key: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)

    def merged_params(self, base: dict[str, Any]) -> dict[str, Any]:
        """Method params over the shared defaults (base -> method)."""
        merged = dict(base)
        merged.update(self.params)
        return merged


class AnalysisDefaults(BaseModel):
    methods: list[str] = Field(default_factory=list)
    params: dict[str, Any] = Field(default_factory=dict)


class AnalysisConfig(BaseModel):
    defaults: AnalysisDefaults = Field(default_factory=AnalysisDefaults)
    methods: list[MethodSpec] = Field(default_factory=list)

    def method(self, method_id: str) -> MethodSpec | None:
        return next((m for m in self.methods if m.id == method_id), None)

    def available_ids(self) -> list[str]:
        return [m.id for m in self.methods if m.available]

    def method_choices(self) -> list[dict[str, str]]:
        """Form choices; unavailable methods carry a disabled marker so the
        engine can reject them and the UI can show the planned badge."""
        return [
            {"value": m.id, "label_key": m.label_key, **({"disabled": "true"} if not m.available else {})}
            for m in self.methods
        ]


class VisibleWhen(BaseModel):
    field: str
    equals: str | None = None    # single-value fields (radio, select)
    includes: str | None = None  # multi fields (checkboxes): value in list


class FieldValidators(BaseModel):
    max_length: int | None = None
    max_files: int | None = None
    allowed_hosts: list[str] | None = None


class FieldSpec(BaseModel):
    name: str
    type: str
    label_key: str
    required: bool = False
    default: str | list[str] | None = None
    # Dotted references into config sections (resolved at load time by
    # _resolve_form_refs): choices keep option lists in one place, so the
    # form YAML never duplicates analysis/formats/models.
    choices_from: str | None = None
    defaults_from: str | None = None
    multi: bool = False         # checkboxes: value is a list of choices
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
    analysis: AnalysisConfig
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
    # web/app/core/config.py -> project root (frontend/ in the monorepo)
    return Path(__file__).resolve().parents[3]


def _load_forms(forms_dir: Path) -> dict[str, FormSpec]:
    forms: dict[str, FormSpec] = {}
    for path in sorted(forms_dir.glob("*.yaml")):
        spec = FormSpec.model_validate(_read_yaml(path))
        forms[spec.id] = spec
    return forms


def _form_ref_sources(settings: Settings) -> dict[str, Any]:
    """Dotted paths a form field may reference via choices_from/defaults_from."""
    return {
        "analysis.methods": settings.analysis.method_choices(),
        "analysis.defaults.methods": list(settings.analysis.defaults.methods),
        "reports.formats": settings.reports.format_choices(),
        "reports.defaults.formats": list(settings.reports.defaults.formats),
    }


def _resolve_form_refs(settings: Settings) -> Settings:
    """Resolve choices_from / defaults_from into field values at load time,
    so option lists live only in the referenced config section."""
    sources = _form_ref_sources(settings)
    forms: dict[str, FormSpec] = {}
    for form_id, form in settings.forms.items():
        fields = []
        for field in form.fields:
            updates: dict[str, Any] = {}
            if field.choices_from:
                if field.choices_from not in sources:
                    raise LookupError(f"form {form_id!r}: unknown choices_from {field.choices_from!r}")
                updates["choices"] = sources[field.choices_from]
            if field.defaults_from:
                if field.defaults_from not in sources:
                    raise LookupError(f"form {form_id!r}: unknown defaults_from {field.defaults_from!r}")
                updates["default"] = sources[field.defaults_from]
            fields.append(field.model_copy(update=updates) if updates else field)
        forms[form_id] = form.model_copy(update={"fields": fields})
    return settings.model_copy(update={"forms": forms})


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
    analysis = AnalysisConfig.model_validate(_read_yaml(root / "config" / "analysis.yaml"))
    theme = ThemeConfig.model_validate(_read_yaml(root / "config" / "theme.yaml"))
    forms = _load_forms(root / "config" / "forms")
    i18n = _read_yaml(root / "i18n" / "ru.yaml")

    settings = Settings(
        app=app,
        upload=upload,
        reports=reports,
        analysis=analysis,
        theme=theme,
        forms=forms,
        i18n=i18n,
        root=root,
    )
    return _apply_env(_resolve_form_refs(settings))


def reload_settings() -> Settings:
    """Drop the cached settings (used by tests to switch config per case)."""
    get_settings.cache_clear()
    return get_settings()
