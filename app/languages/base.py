from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.models.finding import LanguageAnalysis

if TYPE_CHECKING:
    from app.sandbox.models import RunPlan


class LanguageHandler(ABC):
    """Plugin contract for language-specific SAST, DAST, and sandbox boot."""

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

    def detect_runtime(self, target_url: str, fingerprint: dict[str, Any]) -> bool:
        """Return True if this language matches a live HTTP target fingerprint.

        Default is no-op so SAST-only plugins stay valid. Override in handlers
        that support DAST; orchestrator only calls analyze_dast after True.
        """
        return False

    def analyze_dast(
        self,
        target_url: str,
        job_ctx: dict[str, Any] | None = None,
    ) -> LanguageAnalysis:
        """Language-specific dynamic checks against a live target.

        Default returns an empty analysis. Findings should set language=self.id.
        """
        return LanguageAnalysis(language=self.id, meta={"dast": "noop"})

    def detect_runnable(self, root: Path) -> RunPlan | None:
        """Return a sandbox RunPlan if this language can boot a web target.

        Used when the repo has no Dockerfile/compose. Default: not runnable.
        """
        return None
