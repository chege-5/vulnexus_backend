import os
import uuid
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db
from app.auth import get_current_user
from app.rate_limit import limiter
from app.models.db_models import Scan, ScanStatus, User
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()


@router.get("/report/{scan_id}")
@limiter.limit("10/minute")
async def download_report(
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
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan not yet completed")

    reports_dir = os.path.join(settings.UPLOAD_DIR, "reports")
    pdf_path = os.path.join(reports_dir, f"{scan_id}.pdf")
    html_path = os.path.join(reports_dir, f"{scan_id}.html")

    if os.path.exists(pdf_path):
        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename=f"vulnexus_report_{scan_id}.pdf",
        )
    elif os.path.exists(html_path):
        return FileResponse(
            html_path,
            media_type="text/html",
            filename=f"vulnexus_report_{scan_id}.html",
        )
    else:
        raise HTTPException(status_code=404, detail="Report not found")
