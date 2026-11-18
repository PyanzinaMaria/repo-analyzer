"""DAST web-core: SSRF gate, preflight, ZAP baseline, normalization."""

from app.dast.config import get_dast_config
from app.dast.orchestrator import DastOrchestrator

__all__ = ["DastOrchestrator", "get_dast_config"]
