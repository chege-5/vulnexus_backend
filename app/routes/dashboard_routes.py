from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.deps import get_db
from app.auth import get_current_user
from app.rate_limit import limiter
from app.models.db_models import Scan, Vulnerability, ScanStatus, Severity, User
from app.models.pydantic_models import DashboardResponse
from app.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()


@router.get("/dashboard", response_model=DashboardResponse)
@limiter.limit("30/minute")
async def dashboard(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    total = await db.scalar(select(func.count(Scan.id)))
    completed = await db.scalar(
        select(func.count(Scan.id)).where(Scan.status == ScanStatus.COMPLETED)
    )
    failed = await db.scalar(
        select(func.count(Scan.id)).where(Scan.status == ScanStatus.FAILED)
    )
    avg_score = await db.scalar(
        select(func.avg(Scan.overall_score)).where(Scan.overall_score.isnot(None))
    )

    sev_counts = {}
    for sev in Severity:
        count = await db.scalar(
            select(func.count(Vulnerability.id)).where(Vulnerability.severity == sev)
        )
        sev_counts[sev.value] = count or 0

    recent_result = await db.execute(
        select(Scan).order_by(Scan.queued_at.desc()).limit(10)
    )
    recent_scans = [
        {
            "scan_id": str(s.id),
            "target": s.target,
            "type": s.type,
            "status": s.status,
            "overall_score": s.overall_score,
            "queued_at": str(s.queued_at) if s.queued_at else None,
        }
        for s in recent_result.scalars().all()
    ]

    return DashboardResponse(
        total_scans=total or 0,
        completed_scans=completed or 0,
        failed_scans=failed or 0,
        vulnerabilities_by_severity=sev_counts,
        recent_scans=recent_scans,
        average_risk_score=round(avg_score, 2) if avg_score else None,
    )
