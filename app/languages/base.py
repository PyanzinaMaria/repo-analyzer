from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from app.models.finding import LanguageAnalysis


class LanguageHandler(ABC):
    """Plugin contract for language-specific analysis."""

    id: str
    display_name: str
    extensions: tuple[str, ...]

    def __init__(self, enabled: bool = False) -> None:
        self.enabled = enabled

    @abstractmethod
    def detect(self, root: Path) -> bool:
        """Return True if this language is present in the workspace."""

    @abstractmethod
    def analyze(self, root: Path, job_ctx: dict[str, Any] | None = None) -> LanguageAnalysis:
        """Run language analysis and return normalized findings + inventory."""
