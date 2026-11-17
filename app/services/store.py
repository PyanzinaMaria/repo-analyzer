from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.models.project import ProjectInfo, ProjectStatus, ScanInfo, ScanStatus
from app.models.report import ScanResult


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ProjectStore:
    """Filesystem-backed project/scan store for the MVP monolith."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.settings = get_settings()
        self.root = self.settings.data_dir
        self.root.mkdir(parents=True, exist_ok=True)

    def project_dir(self, project_id: str) -> Path:
        return self.root / project_id

    def workspace_dir(self, project_id: str) -> Path:
        return self.project_dir(project_id) / "workspace"

    def _meta_path(self, project_id: str) -> Path:
        return self.project_dir(project_id) / "project.json"

    def _scan_path(self, project_id: str, scan_id: str) -> Path:
        return self.project_dir(project_id) / "scans" / f"{scan_id}.json"

    def _result_path(self, project_id: str, scan_id: str) -> Path:
        return self.project_dir(project_id) / "scans" / f"{scan_id}_result.json"

    def save_project(self, project: ProjectInfo) -> ProjectInfo:
        with self._lock:
            path = self._meta_path(project.id)
            path.parent.mkdir(parents=True, exist_ok=True)
            project.updated_at = _utc_now()
            path.write_text(
                project.model_dump_json(indent=2),
                encoding="utf-8",
            )
            return project

    def get_project(self, project_id: str) -> ProjectInfo | None:
        path = self._meta_path(project_id)
        if not path.exists():
            return None
        return ProjectInfo.model_validate_json(path.read_text(encoding="utf-8"))

    def list_projects(self) -> list[ProjectInfo]:
        items: list[ProjectInfo] = []
        for child in sorted(self.root.iterdir()):
            meta = child / "project.json"
            if meta.exists():
                items.append(ProjectInfo.model_validate_json(meta.read_text(encoding="utf-8")))
        return items

    def update_status(
        self,
        project_id: str,
        status: ProjectStatus,
        error: str | None = None,
        **meta: Any,
    ) -> ProjectInfo:
        project = self.get_project(project_id)
        if project is None:
            raise KeyError(project_id)
        project.status = status
        project.error = error
        if meta:
            project.meta.update(meta)
        return self.save_project(project)

    def save_scan(self, scan: ScanInfo) -> ScanInfo:
        with self._lock:
            path = self._scan_path(scan.project_id, scan.id)
            path.parent.mkdir(parents=True, exist_ok=True)
            scan.updated_at = _utc_now()
            path.write_text(scan.model_dump_json(indent=2), encoding="utf-8")
            return scan

    def get_scan(self, project_id: str, scan_id: str) -> ScanInfo | None:
        path = self._scan_path(project_id, scan_id)
        if not path.exists():
            return None
        return ScanInfo.model_validate_json(path.read_text(encoding="utf-8"))

    def list_scans(self, project_id: str) -> list[ScanInfo]:
        scans_dir = self.project_dir(project_id) / "scans"
        if not scans_dir.exists():
            return []
        items: list[ScanInfo] = []
        for path in sorted(scans_dir.glob("*.json")):
            if path.name.endswith("_result.json"):
                continue
            items.append(ScanInfo.model_validate_json(path.read_text(encoding="utf-8")))
        return items

    def save_result(self, result: ScanResult) -> Path:
        path = self._result_path(result.project_id, result.scan_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        return path

    def get_result(self, project_id: str, scan_id: str) -> ScanResult | None:
        path = self._result_path(project_id, scan_id)
        if not path.exists():
            return None
        return ScanResult.model_validate_json(path.read_text(encoding="utf-8"))

    def reports_dir(self, project_id: str, scan_id: str) -> Path:
        path = self.project_dir(project_id) / "reports" / scan_id
        path.mkdir(parents=True, exist_ok=True)
        return path
