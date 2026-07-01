import uuid
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db
from app import database
from app.auth import get_current_user, get_user_from_token
from app.rate_limit import limiter
from app.models.db_models import Scan, ScanStatus, ScanType, Vulnerability, User
from app.models.db_models import GitHubConnection
from app.services.rbac import Permission, require_permission
from app.models.pydantic_models import (
    ScanUploadResponse,
    ScanURLRequest,
    ScanStatusResponse,
    ScanResultResponse,
    VulnerabilityOut,
    ScanHistoryItem,
)
from app.utils.file_utils import validate_upload, save_upload
from app.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()

ACTIVE_SCAN_STATUSES = [
    ScanStatus.COMPLETED.value,
    ScanStatus.IN_PROGRESS.value,
    ScanStatus.QUEUED.value,
]


class GitHubRepositoryScanRequest(BaseModel):
    organization: str
    repository: str
    branch: str
    folder: str = ""


class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, list[WebSocket]] = {}

    async def connect(self, ws: WebSocket, scan_id: str):
        await ws.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(ws)

    def disconnect(self, ws: WebSocket, scan_id: str):
        if scan_id in self.active_connections:
            self.active_connections[scan_id].remove(ws)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def broadcast_status(self, scan_id: str, message: dict):
        if scan_id in self.active_connections:
            for connection in self.active_connections[scan_id]:
                try:
                    await connection.send_json(message)
                except Exception:
                    pass


manager = ConnectionManager()


@router.websocket("/ws/scan-status/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str, token: str | None = None):
    if not token:
        await websocket.close(code=1008)
        return

    async with database.async_session_maker() as db:
        try:
            user = await get_user_from_token(token, db)
        except HTTPException:
            await websocket.close(code=1008)
            return

        result = await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
        scan = result.scalar_one_or_none()
        if not scan or scan.user_id != user.id:
            await websocket.close(code=1008)
            return

    await manager.connect(websocket, scan_id)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)


async def _count_active_scans(db: AsyncSession, user_id: uuid.UUID) -> int:
    result = await db.execute(
        select(func.count()).select_from(Scan).where(
            Scan.user_id == user_id,
            Scan.status.in_(ACTIVE_SCAN_STATUSES),
        )
    )
    return result.scalar_one()


@router.post("/upload-file", response_model=ScanUploadResponse)
@limiter.limit("10/minute")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCAN_CREATE)),
):
    if not current_user.is_approved:
        raise HTTPException(status_code=403, detail="Your account is not approved by admin. Please contact support.")

    user_scan_count = await _count_active_scans(db, current_user.id)
    if user_scan_count >= current_user.scan_limit:
        raise HTTPException(
            status_code=403,
            detail=f"You have reached your subscription's scan limit ({current_user.scan_limit} scans). Please upgrade your package.",
        )

    if not validate_upload(file):
        raise HTTPException(status_code=400, detail="Invalid file type")

    scan = Scan(
        type=ScanType.FILE.value,
        target=file.filename or "unknown",
        status=ScanStatus.QUEUED.value,
        user_id=current_user.id,
    )
    db.add(scan)
    await db.flush()

    try:
        saved_path = await save_upload(file, scan.id)
    except ValueError as e:
        await db.rollback()
        raise HTTPException(status_code=413, detail=str(e))

    await db.commit()

    from app.celery_app import run_file_scan_task
    run_file_scan_task.delay(str(scan.id), saved_path)

    logger.info(f"Queued file scan {scan.id} for user {current_user.id}")
    return ScanUploadResponse(scan_id=scan.id, status="queued")


@router.post("/scan-url", response_model=ScanUploadResponse)
@limiter.limit("10/minute")
async def scan_url_target(
    request: Request,
    payload: ScanURLRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCAN_CREATE)),
):
    if not current_user.is_approved:
        raise HTTPException(status_code=403, detail="Your account is not approved by admin. Please contact support.")

    user_scan_count = await _count_active_scans(db, current_user.id)
    if user_scan_count >= current_user.scan_limit:
        raise HTTPException(
            status_code=403,
            detail=f"You have reached your subscription's scan limit ({current_user.scan_limit} scans). Please upgrade your package.",
        )

    scan = Scan(
        type=ScanType.URL.value,
        target=str(payload.url),
        status=ScanStatus.QUEUED.value,
        user_id=current_user.id,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    from app.celery_app import run_url_scan_task
    run_url_scan_task.delay(str(scan.id), str(payload.url))

    logger.info(f"Queued URL scan {scan.id} for target {payload.url}")
    return ScanUploadResponse(scan_id=scan.id, status="queued")


@router.post("/scan-github-repository", response_model=ScanUploadResponse)
@limiter.limit("10/minute")
async def scan_github_repository(
    request: Request,
    payload: GitHubRepositoryScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.GITHUB_SCAN)),
):
    if not current_user.is_approved:
        raise HTTPException(status_code=403, detail="Your account is not approved by admin. Please contact support.")

    user_scan_count = await _count_active_scans(db, current_user.id)
    if user_scan_count >= current_user.scan_limit:
        raise HTTPException(
            status_code=403,
            detail=f"You have reached your subscription's scan limit ({current_user.scan_limit} scans). Please upgrade your package.",
        )

    connection_result = await db.execute(select(GitHubConnection).where(GitHubConnection.user_id == current_user.id))
    connection = connection_result.scalar_one_or_none()
    if not connection or not connection.is_connected:
        raise HTTPException(status_code=404, detail="GitHub account is not connected")

    target = f"{payload.organization}/{payload.repository}"
    if payload.folder:
        target = f"{target}/{payload.folder.strip('/')}"

    scan = Scan(
        type=ScanType.GITHUB.value,
        target=target,
        status=ScanStatus.QUEUED.value,
        user_id=current_user.id,
        github_org=payload.organization,
        github_repo=payload.repository,
        github_branch=payload.branch,
        github_folder=payload.folder or None,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    from app.services.tasks import run_github_repo_scan
    run_github_repo_scan.delay(str(scan.id), str(current_user.id), payload.organization, payload.repository, payload.branch, payload.folder or "")

    logger.info(f"Queued GitHub repository scan {scan.id} for {target}")
    return ScanUploadResponse(scan_id=scan.id, status="queued")


@router.get("/scan-status/{scan_id}", response_model=ScanStatusResponse)
@limiter.limit("30/minute")
async def scan_status(
    scan_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCAN_READ)),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    return ScanStatusResponse(
        scan_id=scan.id,
        status=scan.status,
        progress=scan.progress,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
    )


@router.get("/scans", response_model=list[ScanHistoryItem])
@limiter.limit("20/minute")
async def list_scans(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCAN_READ)),
):
    scans_result = await db.execute(
        select(Scan)
        .where(Scan.user_id == current_user.id)
        .order_by(Scan.queued_at.desc())
    )
    scans = scans_result.scalars().all()

    items = []
    for s in scans:
        vuln_count_result = await db.execute(
            select(func.count()).select_from(Vulnerability).where(Vulnerability.scan_id == s.id)
        )
        vuln_count = vuln_count_result.scalar_one()
        items.append(ScanHistoryItem(
            id=s.id,
            type=s.type,
            target=s.target,
            status=s.status,
            overall_score=s.overall_score,
            vulnerability_count=vuln_count,
            queued_at=s.queued_at,
            started_at=s.started_at,
            finished_at=s.finished_at,
        ))
    return items


@router.get("/scan-result/{scan_id}", response_model=ScanResultResponse)
@limiter.limit("20/minute")
async def scan_result(
    scan_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCAN_READ)),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    vulns_result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id)
    )
    vulns = vulns_result.scalars().all()

    vuln_list = [
        VulnerabilityOut(
            id=v.id,
            rule_id=v.rule_id,
            description=v.description,
            severity=v.severity,
            ml_score=v.ml_score,
            cve_id=v.cve_id,
            file_path=v.file_path,
            line_number=v.line_number,
            remediation=v.remediation,
        )
        for v in vulns
    ]

    return ScanResultResponse(
        scan_id=scan.id,
        status=scan.status,
        overall_score=scan.overall_score,
        vulnerabilities=vuln_list,
        target=scan.target,
        type=scan.type,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
    )
