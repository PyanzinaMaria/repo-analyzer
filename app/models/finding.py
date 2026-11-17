from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"
    unknown = "unknown"


class Finding(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity = Severity.unknown
    cwe: str | None = None
    file: str | None = None
    line: int | None = None
    column: int | None = None
    rule_id: str | None = None
    source: str
    language: str
    remediation: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class CodeInventory(BaseModel):
    language: str
    files_count: int = 0
    modules: list[str] = Field(default_factory=list)
    classes: list[str] = Field(default_factory=list)
    functions: list[str] = Field(default_factory=list)
    imports: list[str] = Field(default_factory=list)
    dependency_files: list[str] = Field(default_factory=list)


class LanguageAnalysis(BaseModel):
    language: str
    findings: list[Finding] = Field(default_factory=list)
    inventory: CodeInventory | None = None
    meta: dict[str, Any] = Field(default_factory=dict)
