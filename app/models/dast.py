from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, HttpUrl


class DastScanStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    skipped = "skipped"


class DastScanCreate(BaseModel):
    """Request body for starting a DAST scan against a live HTTP target."""

    target_url: HttpUrl
    max_duration_seconds: int | None = Field(default=None, ge=30, le=3600)
    follow_redirects: bool = True


class DastScanInfo(BaseModel):
    id: str
    status: DastScanStatus
    target_url: str
    enabled_languages: list[str] = Field(default_factory=list)
    findings_count: int = 0
    error: str | None = None
    result_path: str | None = None
