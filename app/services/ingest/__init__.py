from __future__ import annotations

import shutil
import tempfile
import uuid
from pathlib import Path

from app.models.project import ProjectInfo, ProjectSourceType, ProjectStatus
from app.services.ingest.github import GitHubIngestError, clone_github_repo
from app.services.ingest.local import LocalIngestError, copy_local_path, extract_zip
from app.services.store import ProjectStore


class IngestService:
    def __init__(self, store: ProjectStore | None = None) -> None:
        self.store = store or ProjectStore()

    def create_from_local_path(self, local_path: str, name: str | None = None) -> ProjectInfo:
        project_id = uuid.uuid4().hex
        workspace = self.store.workspace_dir(project_id)
        project = ProjectInfo(
            id=project_id,
            name=name or Path(local_path).name,
            source_type=ProjectSourceType.local_path,
            status=ProjectStatus.ingesting,
            source_ref=str(Path(local_path).expanduser()),
            workspace_path=str(workspace),
        )
        self.store.save_project(project)
        try:
            copy_local_path(local_path, workspace)
            return self.store.update_status(project_id, ProjectStatus.ready)
        except Exception as exc:  # noqa: BLE001
            self.store.update_status(project_id, ProjectStatus.failed, error=str(exc))
            raise LocalIngestError(str(exc)) from exc

    def create_from_zip_bytes(
        self,
        content: bytes,
        filename: str = "upload.zip",
        name: str | None = None,
    ) -> ProjectInfo:
        project_id = uuid.uuid4().hex
        workspace = self.store.workspace_dir(project_id)
        project = ProjectInfo(
            id=project_id,
            name=name or Path(filename).stem,
            source_type=ProjectSourceType.zip_upload,
            status=ProjectStatus.ingesting,
            source_ref=filename,
            workspace_path=str(workspace),
        )
        self.store.save_project(project)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                zip_path = Path(tmp) / filename
                zip_path.write_bytes(content)
                extract_zip(zip_path, workspace)
            return self.store.update_status(project_id, ProjectStatus.ready)
        except Exception as exc:  # noqa: BLE001
            self.store.update_status(project_id, ProjectStatus.failed, error=str(exc))
            raise LocalIngestError(str(exc)) from exc

    def create_from_github(self, github_url: str, name: str | None = None) -> ProjectInfo:
        project_id = uuid.uuid4().hex
        workspace = self.store.workspace_dir(project_id)
        project = ProjectInfo(
            id=project_id,
            name=name or github_url.rstrip("/").split("/")[-1].removesuffix(".git"),
            source_type=ProjectSourceType.github,
            status=ProjectStatus.ingesting,
            source_ref=str(github_url),
            workspace_path=str(workspace),
        )
        self.store.save_project(project)
        try:
            clone_github_repo(github_url, workspace)
            return self.store.update_status(project_id, ProjectStatus.ready)
        except Exception as exc:  # noqa: BLE001
            if workspace.exists():
                shutil.rmtree(workspace, ignore_errors=True)
            self.store.update_status(project_id, ProjectStatus.failed, error=str(exc))
            raise GitHubIngestError(str(exc)) from exc


__all__ = [
    "IngestService",
    "LocalIngestError",
    "GitHubIngestError",
]
