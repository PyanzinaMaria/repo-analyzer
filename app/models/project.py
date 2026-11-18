from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl, model_validator


class ProjectSourceType(str, Enum):
    local_path = "local_path"
    zip_upload = "zip_upload"
    github = "github"


class ProjectStatus(str, Enum):
    created = "created"
    ingesting = "ingesting"
    ready = "ready"
    scanning = "scanning"
    completed = "completed"
    failed = "failed"


class ProjectCreate(BaseModel):
    source_type: ProjectSourceType
    local_path: str | None = None
    github_url: HttpUrl | str | None = None
    name: str | None = None

    @model_validator(mode="after")
    def validate_source(self) -> ProjectCreate:
        if self.source_type == ProjectSourceType.local_path and not self.local_path:
            raise ValueError("local_path is required for source_type=local_path")
        if self.source_type == ProjectSourceType.github and not self.github_url:
            raise ValueError("github_url is required for source_type=github")
        if self.source_type == ProjectSourceType.zip_upload:
            raise ValueError("Use multipart upload endpoint for zip_upload")
        return self


class ProjectInfo(BaseModel):
    id: str
    name: str
    source_type: ProjectSourceType
    status: ProjectStatus
    source_ref: str | None = None
    workspace_path: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    error: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)


class ScanStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class ScanInfo(BaseModel):
    id: str
    project_id: str
    status: ScanStatus
    enabled_languages: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    findings_count: int = 0
    error: str | None = None
    result_path: str | None = None


class ScanCreate(BaseModel):
    """Optional per-scan overrides. Empty body keeps yaml/env defaults.

    ``methods`` holds runner keys (see ``app/analysis/registry.py``):
    ``static``, ``ai``, ... The frontend's method ids (sast, llm_agentic, ...)
    are mapped to runner keys by the worker via frontend/config/analysis.yaml.
    """

    enable_ai: bool | None = None
    methods: list[str] | None = None


class ReportFormat(str, Enum):
    json = "json"
    markdown = "markdown"


ReportKind = Literal["security", "fstec"]
