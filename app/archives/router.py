from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import current_principal
from app.archives.schema import ArchiveRequest
from app.archives.service import ArchiveService
from app.core.security import Principal
from app.database import get_connection

router = APIRouter(prefix="/api/archives", tags=["资料封存"])


def service() -> ArchiveService:
    return ArchiveService(get_connection())


@router.post("", status_code=200)
def create_archive(payload: ArchiveRequest, principal: Principal = Depends(current_principal)) -> dict:
    """按范围与截止时刻生成封存；相同范围与脱敏策略的请求复用不可变版本。"""
    return service().create_or_reuse(principal, payload.model_dump())


@router.get("")
def list_archives(
    scope: str | None = None,
    status: str | None = Query(default=None, pattern="^(building|sealed|failed)$"),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    principal: Principal = Depends(current_principal),
) -> dict:
    return service().list_archives(principal, scope=scope, status_filter=status, page=page, size=size)


@router.get("/{archive_id}/status")
def archive_status(archive_id: int, principal: Principal = Depends(current_principal)) -> dict:
    return service().status(principal, archive_id)


@router.get("/{archive_id}/download")
def download_archive(archive_id: int, principal: Principal = Depends(current_principal)) -> dict:
    return service().download(principal, archive_id)
