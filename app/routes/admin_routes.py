import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db
from app.auth import require_role
from app.models.db_models import User, Scan, Vulnerability, Notification, ScanStatus, Severity
from app.services.integrations import integration_manager
from app.services.rbac import log_audit_event

router = APIRouter()
admin_dependency = Depends(require_role("admin"))


class UserApprovalRequest(BaseModel):
    is_approved: bool


class UserLimitRequest(BaseModel):
    scan_limit: int


class UserSubscriptionRequest(BaseModel):
    subscription_tier: str
    subscription_status: str


class CommunicationRequest(BaseModel):
    user_id: Optional[str] = None
    title: str
    message: str
    type: str = "info"
    send_email: bool = True


@router.get("/admin/users", dependencies=[admin_dependency])
async def list_users(db: AsyncSession = Depends(get_db)):
    users_result = await db.execute(select(User))
    users = []
    for u in users_result.scalars().all():
        scan_count = await db.scalar(
            select(func.count()).select_from(Scan).where(Scan.user_id == u.id)
        )
        users.append({
            "_id": str(u.id),
            "email": u.email,
            "role": u.role,
            "name": u.name,
            "phone": u.phone,
            "carrier": u.carrier,
            "fav_programming_languages": u.fav_programming_languages,
            "company": u.company,
            "job_role": u.job_role,
            "security_focus": u.security_focus,
            "subscription_tier": u.subscription_tier,
            "subscription_status": u.subscription_status,
            "scan_limit": u.scan_limit,
            "is_approved": u.is_approved,
            "pending_approval": u.pending_approval,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "scan_count": scan_count or 0,
        })
    return users


@router.post("/admin/users/{user_id}/approve", dependencies=[admin_dependency])
async def approve_user(user_id: str, body: UserApprovalRequest, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_approved = body.is_approved
    db.add(Notification(
        user_id=user.id,
        title="Account Status Updated",
        message=f"Your account status has been updated. Approved: {body.is_approved}",
        type="info" if body.is_approved else "critical",
    ))
    await log_audit_event(db, None, "admin.user.approve", "user", user_id, {"is_approved": body.is_approved}, request.client.host if request.client else None)
    await db.commit()
    return {"message": f"User approval status updated to {body.is_approved}"}


@router.post("/admin/users/{user_id}/limit", dependencies=[admin_dependency])
async def update_user_limit(user_id: str, body: UserLimitRequest, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.scan_limit = body.scan_limit
    db.add(Notification(
        user_id=user.id,
        title="Scan Limit Updated",
        message=f"Your scan limit has been updated to {body.scan_limit} scans.",
        type="info",
    ))
    await log_audit_event(db, None, "admin.user.limit", "user", user_id, {"scan_limit": body.scan_limit}, request.client.host if request.client else None)
    await db.commit()
    return {"message": f"User scan limit updated to {body.scan_limit}"}


@router.post("/admin/users/{user_id}/subscription", dependencies=[admin_dependency])
async def update_user_subscription(user_id: str, body: UserSubscriptionRequest, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.subscription_tier = body.subscription_tier.lower()
    user.subscription_status = body.subscription_status
    db.add(Notification(
        user_id=user.id,
        title="Subscription Tier Updated",
        message=f"Your subscription tier is now {body.subscription_tier.upper()} ({body.subscription_status}).",
        type="info",
    ))
    await log_audit_event(db, None, "admin.user.subscription", "user", user_id, body.model_dump(), request.client.host if request.client else None)
    await db.commit()
    return {"message": "User subscription updated successfully"}


@router.post("/admin/communicate", dependencies=[admin_dependency])
async def send_communication(body: CommunicationRequest, request: Request, db: AsyncSession = Depends(get_db)):
    notif = Notification(
        user_id=uuid.UUID(body.user_id) if body.user_id else None,
        title=body.title,
        message=body.message,
        type=body.type,
    )
    db.add(notif)
    await log_audit_event(db, None, "admin.communicate", "notification", body.user_id, {"title": body.title, "type": body.type, "send_email": body.send_email}, request.client.host if request.client else None)
    await db.commit()

    if body.user_id:
        print(f"[EMAIL] To: {body.user_id} | Subject: {body.title} | Content: {body.message}")
    else:
        print(f"[EMAIL] Broadcast To All | Subject: {body.title} | Content: {body.message}")

    return {"message": "Communication sent successfully", "email_sent": body.send_email}


@router.get("/admin/analytics", dependencies=[admin_dependency])
async def get_admin_analytics(db: AsyncSession = Depends(get_db)):
    total_users = await db.scalar(select(func.count()).select_from(User))
    total_scans = await db.scalar(select(func.count()).select_from(Scan))
    completed_scans = await db.scalar(
        select(func.count()).select_from(Scan).where(Scan.status == ScanStatus.COMPLETED.value)
    )
    failed_scans = await db.scalar(
        select(func.count()).select_from(Scan).where(Scan.status == ScanStatus.FAILED.value)
    )
    active_threats = await db.scalar(select(func.count()).select_from(Vulnerability))

    tiers = ["free", "starter", "developer", "team", "enterprise"]
    tier_counts = {}
    for tier in tiers:
        tier_counts[tier] = await db.scalar(
            select(func.count()).select_from(User).where(User.subscription_tier == tier)
        ) or 0

    severity_breakdown = {}
    for sev in Severity:
        severity_breakdown[sev.value] = await db.scalar(
            select(func.count()).select_from(Vulnerability).where(Vulnerability.severity == sev.value)
        ) or 0

    recent_result = await db.execute(
        select(Scan).order_by(Scan.queued_at.desc()).limit(10)
    )
    recent_scans = []
    for s in recent_result.scalars().all():
        user_email = "Unknown"
        if s.user_id:
            user_result = await db.execute(select(User).where(User.id == s.user_id))
            user = user_result.scalar_one_or_none()
            if user:
                user_email = user.email
        recent_scans.append({
            "scan_id": str(s.id),
            "target": s.target,
            "type": s.type,
            "status": s.status,
            "overall_score": s.overall_score,
            "user_email": user_email,
            "queued_at": str(s.queued_at) if s.queued_at else None,
        })

    scan_trend = []
    for i in range(6, -1, -1):
        day = datetime.now(timezone.utc) - timedelta(days=i)
        day_str = day.strftime("%a")
        start_of_day = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
        end_of_day = start_of_day + timedelta(days=1)

        scans_count = await db.scalar(
            select(func.count()).select_from(Scan).where(
                Scan.queued_at >= start_of_day,
                Scan.queued_at < end_of_day,
            )
        )
        threats_count = await db.scalar(
            select(func.count()).select_from(Vulnerability).where(
                Vulnerability.created_at >= start_of_day,
                Vulnerability.created_at < end_of_day,
            )
        )
        scan_trend.append({
            "date": day_str,
            "scans": scans_count or 0,
            "threats": threats_count or 0,
        })

    return {
        "total_users": total_users or 0,
        "total_scans": total_scans or 0,
        "completed_scans": completed_scans or 0,
        "failed_scans": failed_scans or 0,
        "active_threats": active_threats or 0,
        "tier_counts": tier_counts,
        "severity_breakdown": severity_breakdown,
        "recent_scans": recent_scans,
        "scan_trend": scan_trend,
    }


@router.get("/admin/providers/health", dependencies=[admin_dependency])
async def provider_health():
    health = await integration_manager.health_check_all()
    return [
        {
            "provider": item.provider,
            "enabled": item.enabled,
            "healthy": item.healthy,
            "message": item.message,
            "endpoint": item.endpoint,
            "checked_at": item.checked_at.isoformat(),
            "details": item.details,
        }
        for item in health.values()
    ]
