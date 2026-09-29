from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Response

from app.api.dependencies import current_principal
from app.archive.schemas import ArchiveCreate
from app.archive.service import ArchiveService
from app.core.pagination import Page
from app.core.security import Principal

router = APIRouter(prefix="/api/archives", tags=["教学资料封存"])


def service() -> ArchiveService:
    return ArchiveService()


@router.post("", status_code=201)
def create_archive(payload: ArchiveCreate, response: Response, principal: Principal = Depends(current_principal)):
    result = service().create(payload.model_dump(), principal)
    if result["reused"]:
        response.status_code = 200
    return result


@router.get("")
def list_archives(
    status: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    principal: Principal = Depends(current_principal),
):
    return service().list(principal, status=status, page=Page(page, size))


@router.get("/explain")
def explain_archive(
    project_code: str | None = None,
    template_code: str | None = None,
    requested_by: str | None = None,
    principal: Principal = Depends(current_principal),
):
    scope = {key: value for key, value in {"project_code": project_code, "template_code": template_code, "requested_by": requested_by}.items() if value}
    return service().explain(principal, scope)


@router.get("/{archive_id}")
def get_archive(archive_id: int, principal: Principal = Depends(current_principal)):
    return service().get(archive_id, principal)


@router.get("/{archive_id}/download")
def download_archive(archive_id: int, principal: Principal = Depends(current_principal)):
    return service().download(archive_id, principal)
