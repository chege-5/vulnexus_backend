import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.deps import get_db
from app.models.db_models import Notification, User
from app.rate_limit import limiter
from app.services.rbac import Permission, require_permission

router = APIRouter()


def _serialize_notification(notif: Notification) -> dict:
    created = notif.created_at
    time_label = created.strftime("%Y-%m-%d %H:%M") if isinstance(created, datetime) else str(created or "")
    return {
        "id": str(notif.id),
        "type": notif.type,
        "title": notif.title,
        "message": notif.message,
        "read": notif.is_read,
        "time": time_label,
        "created_at": created.isoformat() if isinstance(created, datetime) else None,
    }


@router.get("/notifications")
@limiter.limit("30/minute")
async def list_notifications(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.NOTIFICATION_READ)),
):
    result = await db.execute(
        select(Notification)
        .where(or_(Notification.user_id == current_user.id, Notification.user_id.is_(None)))
        .order_by(Notification.created_at.desc())
        .limit(100)
    )
    return [_serialize_notification(n) for n in result.scalars().all()]


@router.patch("/notifications/{notification_id}/read")
@limiter.limit("30/minute")
async def mark_notification_read(
    notification_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.NOTIFICATION_READ)),
):
    result = await db.execute(select(Notification).where(Notification.id == notification_id))
    notif = result.scalar_one_or_none()
    if not notif:
        raise HTTPException(status_code=404, detail="Notification not found")
    if notif.user_id is not None and notif.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    notif.is_read = True
    await db.commit()
    return {"message": "Notification marked as read"}


@router.post("/notifications/read-all")
@limiter.limit("10/minute")
async def mark_all_notifications_read(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.NOTIFICATION_READ)),
):
    await db.execute(
        update(Notification)
        .where(
            or_(Notification.user_id == current_user.id, Notification.user_id.is_(None)),
            Notification.is_read.is_(False),
        )
        .values(is_read=True)
    )
    await db.commit()
    return {"message": "All notifications marked as read"}


@router.delete("/notifications/{notification_id}")
@limiter.limit("30/minute")
async def delete_notification(
    notification_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.NOTIFICATION_READ)),
):
    result = await db.execute(select(Notification).where(Notification.id == notification_id))
    notif = result.scalar_one_or_none()
    if not notif:
        raise HTTPException(status_code=404, detail="Notification not found")
    if notif.user_id is not None and notif.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    await db.delete(notif)
    await db.commit()
    return {"message": "Notification deleted"}
