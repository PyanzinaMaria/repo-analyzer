from __future__ import annotations

from functools import lru_cache

from app.dast import DastOrchestrator
from app.dast.store import DastStore
from app.services.ingest import IngestService
from app.services.scan import ScanOrchestrator
from app.services.store import ProjectStore


@lru_cache
def get_store() -> ProjectStore:
    return ProjectStore()


@lru_cache
def get_ingest_service() -> IngestService:
    return IngestService(store=get_store())


@lru_cache
def get_scan_orchestrator() -> ScanOrchestrator:
    return ScanOrchestrator(store=get_store())


@lru_cache
def get_dast_store() -> DastStore:
    return DastStore()


@lru_cache
def get_dast_orchestrator() -> DastOrchestrator:
    return DastOrchestrator(store=get_dast_store())
