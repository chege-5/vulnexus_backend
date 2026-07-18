import uuid
import asyncio
import ipaddress
import socket
from urllib.parse import urlparse
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db
from app import database
from app.auth import get_current_user, get_user_from_token
from app.config import settings
from app.services.targets import InvalidTargetError, normalize_target
from app.services.ai.explanations import AIExplanationUnavailable, ai_explanation_service
from app.rate_limit import limiter
from app.models.db_models import Scan, ScanFile, ScanStatus, ScanType, Vulnerability, User
from app.models.db_models import GitHubConnection
from app.services.rbac import Permission, require_permission
from app.models.pydantic_models import (
    AIReviewStatusResponse,
    ScanUploadResponse,
    ScanURLRequest,
    ScanStatusResponse,
    ScanResultResponse,
    VulnerabilityOut,
    ScanHistoryItem,
)
from app.utils.cache import cache
from app.utils.file_utils import validate_upload, save_upload, cleanup_scan_dir
from app.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()

ACTIVE_SCAN_STATUSES = [
    ScanStatus.IN_PROGRESS.value,
    ScanStatus.QUEUED.value,
]


class GitHubRepositoryScanRequest(BaseModel):
    organization: str
    repository: str
    branch: str
    folder: str = ""
    project_id: uuid.UUID | None = None


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
            cached_progress = await cache.get("scan_progress", scan_id)
            if cached_progress:
                await websocket.send_json(cached_progress)
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=2)
            except asyncio.TimeoutError:
                continue
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


async def _assert_allowed_scan_target(target_url: str):
    try:
        return await normalize_target(target_url)
    except InvalidTargetError as exc:
        if "could not be resolved" in str(exc):
            raise HTTPException(status_code=400, detail="Unable to resolve scan target") from exc
        raise HTTPException(status_code=400, detail=str(exc)) from exc


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
    normalized_target = await _assert_allowed_scan_target(str(payload.url))
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
        target=normalized_target.normalized_url,
        status=ScanStatus.QUEUED.value,
        user_id=current_user.id,
        project_id=payload.project_id,
        result_metadata={"target": normalized_target.as_metadata()},
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    from app.celery_app import run_url_scan_task
    run_url_scan_task.delay(str(scan.id), normalized_target.normalized_url)

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
        project_id=payload.project_id,
        github_org=payload.organization,
        github_repo=payload.repository,
        github_branch=payload.branch,
        github_folder=payload.folder or None,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    from app.celery_app import run_github_scan_task
    run_github_scan_task.delay(str(scan.id), str(current_user.id), payload.organization, payload.repository, payload.branch, payload.folder or "")

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

    cached_progress = await cache.get("scan_progress", str(scan.id))
    if cached_progress:
        return ScanStatusResponse(
            scan_id=scan.id,
            status=cached_progress.get("status", scan.status),
            ai_review_status=scan.ai_review_status,
            ai_review_error=scan.ai_review_error,
            progress=int(cached_progress.get("progress", scan.progress) or 0),
            stage=cached_progress.get("stage"),
            message=cached_progress.get("message"),
            error_message=cached_progress.get("error_message") or scan.error_message,
            details=cached_progress.get("details") or {},
            started_at=scan.started_at,
            finished_at=cached_progress.get("finished_at") or scan.finished_at,
        )

    return ScanStatusResponse(
        scan_id=scan.id,
        status=scan.status,
        ai_review_status=scan.ai_review_status,
        ai_review_error=scan.ai_review_error,
        progress=scan.progress,
        stage=None,
        message=scan.error_message,
        error_message=scan.error_message,
        details={},
        started_at=scan.started_at,
        finished_at=scan.finished_at,
    )


@router.get("/scans/{scan_id}/ai-review-status", response_model=AIReviewStatusResponse)
@limiter.limit("30/minute")
async def ai_review_status(
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

    metadata = scan.result_metadata or {}
    return AIReviewStatusResponse(
        scan_id=scan.id,
        ai_review_status=scan.ai_review_status,
        ai_review_error=scan.ai_review_error,
        review=metadata.get("ai_review") if scan.ai_review_status == "completed" else None,
        enhanced_report_ready=(metadata.get("enhanced_report") or {}).get("status") == "ready",
    )


@router.get("/scans", response_model=list[ScanHistoryItem])
@limiter.limit("20/minute")
async def list_scans(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCAN_READ)),
):
    scans_result = await db.execute(
        select(Scan)
        .where(Scan.user_id == current_user.id)
        .order_by(Scan.queued_at.desc())
        .offset(max(offset, 0))
        .limit(min(max(limit, 1), 100))
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


@router.post("/scans/{scan_id}/cancel", response_model=ScanStatusResponse)
async def cancel_scan(
    scan_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCAN_UPDATE)),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in {ScanStatus.QUEUED.value, ScanStatus.IN_PROGRESS.value}:
        raise HTTPException(status_code=400, detail="Only queued or running scans can be canceled")
    scan.status = ScanStatus.CANCELED.value
    scan.error_message = "Canceled by user"
    await db.commit()
    await cache.set("scan_progress", str(scan.id), {"scan_id": str(scan.id), "status": scan.status, "progress": scan.progress, "stage": "canceled", "message": "Scan canceled", "error_message": scan.error_message, "details": {}})
    return ScanStatusResponse(scan_id=scan.id, status=scan.status, progress=scan.progress, stage="canceled", message="Scan canceled", error_message=scan.error_message)


@router.post("/scans/{scan_id}/retry", response_model=ScanUploadResponse)
async def retry_scan(
    scan_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCAN_CREATE)),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id))
    original = result.scalar_one_or_none()
    if not original:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = Scan(
        type=original.type,
        target=original.target,
        status=ScanStatus.QUEUED.value,
        user_id=current_user.id,
        organization_id=original.organization_id,
        project_id=original.project_id,
        github_org=original.github_org,
        github_repo=original.github_repo,
        github_branch=original.github_branch,
        github_folder=original.github_folder,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    if scan.type == ScanType.URL.value:
        from app.celery_app import run_url_scan_task
        run_url_scan_task.delay(str(scan.id), scan.target)
    elif scan.type == ScanType.GITHUB.value:
        from app.celery_app import run_github_scan_task
        run_github_scan_task.delay(str(scan.id), str(current_user.id), scan.github_org or "", scan.github_repo or "", scan.github_branch or "main", scan.github_folder or "")
    else:
        file_result = await db.execute(select(ScanFile).where(ScanFile.scan_id == original.id).limit(1))
        scan_file = file_result.scalar_one_or_none()
        if not scan_file:
            raise HTTPException(status_code=400, detail="Original uploaded file is no longer available")
        from app.celery_app import run_file_scan_task
        run_file_scan_task.delay(str(scan.id), scan_file.path)

    return ScanUploadResponse(scan_id=scan.id, status=scan.status)


@router.delete("/scans/{scan_id}")
async def delete_scan(
    scan_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCAN_DELETE)),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    await db.delete(scan)
    await db.commit()
    cleanup_scan_dir(scan_id)
    return {"message": "Scan deleted"}


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
            cvss_score=v.cvss_score,
            cwe_ids=v.cwe_ids,
            owasp_category=v.owasp_category,
            nist_control=v.nist_control,
            mitre_technique=v.mitre_technique,
            known_exploit=v.known_exploit,
            references=v.references,
            status=v.status,
            assigned_to_id=v.assigned_to_id,
        )
        for v in vulns
    ]

    return ScanResultResponse(
        scan_id=scan.id,
        status=scan.status,
        ai_review_status=scan.ai_review_status,
        ai_review_error=scan.ai_review_error,
        overall_score=scan.overall_score,
        vulnerabilities=vuln_list,
        target=scan.target,
        type=scan.type,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        metadata={key: value for key, value in (scan.result_metadata or {}).items() if not key.startswith("_")},
    )


@router.post("/scans/{scan_id}/ai-summary")
@limiter.limit("10/minute")
async def explain_scan_with_ai(
    scan_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.AI_QUERY)),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.user_id != current_user.id and current_user.role not in {"admin", "super_admin"}:
        raise HTTPException(status_code=403, detail="Access denied")
    if scan.status != ScanStatus.COMPLETED.value:
        raise HTTPException(status_code=409, detail="AI explanation is available after scan completion")
    findings_result = await db.execute(select(Vulnerability).where(Vulnerability.scan_id == scan.id).order_by(Vulnerability.created_at.asc()))
    findings = findings_result.scalars().all()
    payload = [
        {
            "rule_id": finding.rule_id,
            "description": finding.description,
            "severity": finding.severity,
            "remediation": finding.remediation,
            "cwe_ids": finding.cwe_ids or [],
        }
        for finding in findings
    ]
    try:
        return await ai_explanation_service.explain_scan(target=scan.target, findings=payload, score=scan.overall_score)
    except AIExplanationUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
