from __future__ import annotations

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from app.api.deps import get_ingest_service, get_store
from app.models.project import ProjectCreate, ProjectInfo, ProjectSourceType
from app.services.ingest import GitHubIngestError, LocalIngestError

router = APIRouter(prefix="/api/v1/projects", tags=["projects"])


@router.get("", response_model=list[ProjectInfo])
def list_projects() -> list[ProjectInfo]:
    return get_store().list_projects()


@router.get("/{project_id}", response_model=ProjectInfo)
def get_project(project_id: str) -> ProjectInfo:
    project = get_store().get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.post("", response_model=ProjectInfo, status_code=201)
def create_project(payload: ProjectCreate) -> ProjectInfo:
    ingest = get_ingest_service()
    try:
        if payload.source_type == ProjectSourceType.local_path:
            return ingest.create_from_local_path(payload.local_path or "", payload.name)
        if payload.source_type == ProjectSourceType.github:
            return ingest.create_from_github(str(payload.github_url), payload.name)
    except (LocalIngestError, GitHubIngestError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    raise HTTPException(status_code=400, detail="Unsupported source_type")


@router.post("/upload", response_model=ProjectInfo, status_code=201)
async def upload_zip(
    file: UploadFile = File(...),
    name: str | None = Form(default=None),
) -> ProjectInfo:
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip uploads are supported")
    content = await file.read()
    try:
        return get_ingest_service().create_from_zip_bytes(content, file.filename, name)
    except LocalIngestError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
