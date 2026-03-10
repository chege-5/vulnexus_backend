import uuid
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, BackgroundTasks, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.deps import get_db
from app.auth import get_current_user
from app.rate_limit import limiter
from app.models.db_models import Scan, ScanStatus, ScanType, Vulnerability, User
from app.models.pydantic_models import (
    ScanUploadResponse,
    ScanURLRequest,
    ScanStatusResponse,
    ScanResultResponse,
    VulnerabilityOut,
)
from app.utils.file_utils import validate_upload, save_upload
from app.services.tasks import run_file_scan, run_url_scan
from app.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()


@router.post("/upload-file", response_model=ScanUploadResponse)
@limiter.limit("10/minute")
async def upload_file(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not validate_upload(file):
        raise HTTPException(status_code=400, detail="Invalid file type")

    scan = Scan(
        type=ScanType.FILE,
        target=file.filename or "unknown",
        status=ScanStatus.QUEUED,
        user_id=current_user.id,
    )
    db.add(scan)
    await db.flush()

    try:
        saved_path = await save_upload(file, scan.id)
    except ValueError as e:
        raise HTTPException(status_code=413, detail=str(e))

    await db.commit()
    background_tasks.add_task(run_file_scan, scan.id, saved_path)
    return ScanUploadResponse(scan_id=scan.id, status="queued")


@router.post("/scan-url", response_model=ScanUploadResponse)
@limiter.limit("10/minute")
async def scan_url(
    request: Request,
    body: ScanURLRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    target = str(body.url)
    scan = Scan(
        type=ScanType.URL,
        target=target,
        status=ScanStatus.QUEUED,
        user_id=current_user.id,
    )
    db.add(scan)
    await db.commit()
    background_tasks.add_task(run_url_scan, scan.id, target)
    return ScanUploadResponse(scan_id=scan.id, status="queued")


@router.get("/scan-status/{scan_id}", response_model=ScanStatusResponse)
@limiter.limit("30/minute")
async def scan_status(
    scan_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = await db.get(Scan, scan_id)
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


@router.get("/scan-result/{scan_id}", response_model=ScanResultResponse)
@limiter.limit("20/minute")
async def scan_result(
    scan_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id)
    )
    vulns = result.scalars().all()

    vuln_list = [
        VulnerabilityOut(
            id=v.id,
            rule_id=v.rule_id,
            description=v.description,
            severity=v.severity.value if hasattr(v.severity, "value") else v.severity,
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
