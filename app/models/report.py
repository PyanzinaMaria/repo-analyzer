from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from app.models.finding import CodeInventory, Finding


class ScanResult(BaseModel):
    scan_id: str
    project_id: str
    project_name: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    enabled_languages: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    inventories: list[CodeInventory] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    meta: dict[str, Any] = Field(default_factory=dict)


class ReportBundle(BaseModel):
    scan_id: str
    security_json_path: str
    security_md_path: str
    fstec_md_path: str
