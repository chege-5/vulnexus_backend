import csv
import io
import uuid
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_role
from app.deps import get_db
from app.models.db_models import AdminWorkspace, AuditLog, FindingComment, FindingHistory, FindingStatus, Notification, Scan, ScanFile, ScanStatus, ScanType, Severity, User, Vulnerability
from app.services.email import queue_transactional_email
from app.services.integrations import integration_manager
from app.services.rbac import log_audit_event

router = APIRouter()
admin_dependency = Depends(require_role("admin"))

TIER_LIMITS = {"free": 10, "starter": 30, "developer": 100, "team": 500, "enterprise": 99999}
SubscriptionTier = Literal["free", "starter", "developer", "team", "enterprise"]
SubscriptionStatus = Literal["active", "trial", "past_due", "canceled"]
NotificationType = Literal["info", "low", "medium", "critical"]
FindingStatusValue = Literal["open", "resolved", "ignored", "false_positive"]

DEFAULT_WORKSPACE_SETTINGS = {
    "notification_preferences": {
        "pending_approvals": True,
        "critical_findings": True,
        "provider_outages": True,
        "failed_scan_spikes": True,
    },
    "saved_views": [],
    "templates": [
        {"id": "incident", "name": "Security incident", "type": "critical", "title": "Security incident update", "message": "We are investigating a security event affecting the VulNexus service."},
        {"id": "maintenance", "name": "Maintenance notice", "type": "info", "title": "Planned maintenance", "message": "VulNexus will undergo planned maintenance during the announced window."},
        {"id": "scan-reliability", "name": "Scan reliability", "type": "medium", "title": "Scan service update", "message": "We are monitoring scan reliability and will share another update when service is stable."},
    ],
}


class UserApprovalRequest(BaseModel):
    is_approved: bool


class UserLimitRequest(BaseModel):
    scan_limit: int = Field(ge=0, le=99999)


class UserSubscriptionRequest(BaseModel):
    subscription_tier: SubscriptionTier
    subscription_status: SubscriptionStatus = "active"


class CommunicationRequest(BaseModel):
    user_id: Optional[uuid.UUID] = None
    title: str = Field(min_length=1, max_length=255)
    message: str = Field(min_length=1, max_length=10000)
    type: NotificationType = "info"
    send_email: bool = False


class BulkApprovalRequest(BaseModel):
    user_ids: list[uuid.UUID] = Field(min_length=1, max_length=100)
    is_approved: bool
    reason: str = Field(default="", max_length=500)


class FindingUpdateRequest(BaseModel):
    status: FindingStatusValue | None = None
    assigned_to_id: uuid.UUID | None = None
    clear_assignment: bool = False
    comment: str = Field(default="", max_length=2000)


class WorkspaceUpdateRequest(BaseModel):
    notification_preferences: dict[str, bool] | None = None
    saved_views: list[dict[str, Any]] | None = Field(default=None, max_length=50)
    templates: list[dict[str, Any]] | None = Field(default=None, max_length=25)


class SavedViewRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    path: str = Field(min_length=1, max_length=120)
    filters: dict[str, Any] = Field(default_factory=dict)


def _serialize_user(user: User, scan_count: int) -> dict:
    return {
        "_id": str(user.id), "email": user.email, "role": user.role, "name": user.name,
        "phone": user.phone, "carrier": user.carrier,
        "fav_programming_languages": user.fav_programming_languages or [], "company": user.company,
        "job_role": user.job_role, "security_focus": user.security_focus,
        "subscription_tier": user.subscription_tier, "subscription_status": user.subscription_status,
        "scan_limit": user.scan_limit, "is_approved": user.is_approved,
        "pending_approval": user.pending_approval,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login": user.last_login.isoformat() if user.last_login else None,
        "scan_count": scan_count or 0,
    }


async def _get_user(db: AsyncSession, user_id: uuid.UUID) -> User:
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


async def _get_workspace(db: AsyncSession, admin: User) -> AdminWorkspace:
    workspace = (await db.execute(select(AdminWorkspace).where(AdminWorkspace.owner_id == admin.id))).scalar_one_or_none()
    if workspace:
        return workspace
    workspace = AdminWorkspace(owner_id=admin.id, settings=deepcopy(DEFAULT_WORKSPACE_SETTINGS))
    db.add(workspace)
    await db.flush()
    return workspace


def _finding_payload(finding: Vulnerability, scan: Scan, owner_email: str | None) -> dict:
    return {
        "id": str(finding.id),
        "title": finding.rule_id or "Security finding",
        "description": finding.description,
        "severity": finding.severity,
        "status": finding.status,
        "target": scan.target,
        "scan_id": str(scan.id),
        "owner_email": owner_email or "Unknown",
        "cve_id": finding.cve_id,
        "cvss_score": finding.cvss_score,
        "known_exploit": finding.known_exploit,
        "assigned_to_id": str(finding.assigned_to_id) if finding.assigned_to_id else None,
        "created_at": finding.created_at.isoformat() if finding.created_at else None,
    }


@router.get("/admin/users", dependencies=[admin_dependency])
async def list_users(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=25, ge=1, le=100),
    query: str = Query(default="", max_length=120),
    approval: Literal["pending", "approved", "blocked"] | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    filters = []
    if query.strip():
        pattern = f"%{query.strip()}%"
        filters.append(or_(User.email.ilike(pattern), User.name.ilike(pattern), User.company.ilike(pattern), User.role.ilike(pattern)))
    if approval == "pending":
        filters.append(User.pending_approval.is_(True))
    elif approval == "approved":
        filters.append(User.is_approved.is_(True))
    elif approval == "blocked":
        filters.append(User.is_approved.is_(False), User.pending_approval.is_(False))

    total = await db.scalar(select(func.count()).select_from(User).where(*filters)) or 0
    result = await db.execute(
        select(User, func.count(Scan.id).label("scan_count"))
        .outerjoin(Scan, Scan.user_id == User.id)
        .where(*filters)
        .group_by(User.id)
        .order_by(User.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    return {
        "items": [_serialize_user(user, scan_count) for user, scan_count in result.all()],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.get("/admin/users/{user_id}", dependencies=[admin_dependency])
async def get_user_detail(user_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    user = await _get_user(db, user_id)
    scan_count = await db.scalar(select(func.count()).select_from(Scan).where(Scan.user_id == user.id)) or 0
    scans_result = await db.execute(select(Scan).where(Scan.user_id == user.id).order_by(Scan.queued_at.desc()).limit(20))
    findings_result = await db.execute(
        select(Vulnerability, Scan)
        .join(Scan, Vulnerability.scan_id == Scan.id)
        .where(Scan.user_id == user.id)
        .order_by(Vulnerability.created_at.desc())
        .limit(25)
    )
    status_counts = {}
    for status in FindingStatus:
        status_counts[status.value] = await db.scalar(
            select(func.count()).select_from(Vulnerability).join(Scan, Vulnerability.scan_id == Scan.id).where(Scan.user_id == user.id, Vulnerability.status == status.value)
        ) or 0
    audit_result = await db.execute(select(AuditLog).where(AuditLog.resource_id == str(user.id)).order_by(AuditLog.created_at.desc()).limit(20))
    return {
        "user": _serialize_user(user, scan_count),
        "scan_count": scan_count,
        "scans": [{"id": str(scan.id), "target": scan.target, "type": scan.type, "status": scan.status, "overall_score": scan.overall_score, "queued_at": scan.queued_at.isoformat() if scan.queued_at else None} for scan in scans_result.scalars().all()],
        "findings": [_finding_payload(finding, scan, user.email) for finding, scan in findings_result.all()],
        "finding_status_counts": status_counts,
        "audit_events": [{"id": str(item.id), "action": item.action, "details": item.details or {}, "created_at": item.created_at.isoformat() if item.created_at else None} for item in audit_result.scalars().all()],
    }


@router.post("/admin/users/{user_id}/approve", dependencies=[admin_dependency])
async def approve_user(
    user_id: uuid.UUID,
    body: UserApprovalRequest,
    request: Request,
    current_admin: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    user = await _get_user(db, user_id)
    if user.id == current_admin.id and not body.is_approved:
        raise HTTPException(status_code=400, detail="You cannot block your own admin account")
    user.is_approved = body.is_approved
    user.pending_approval = False
    db.add(Notification(user_id=user.id, title="Account Status Updated", message=f"Your account status is now {'approved' if body.is_approved else 'blocked'}.", type="info" if body.is_approved else "critical"))
    await log_audit_event(db, str(current_admin.id), "admin.user.approval_updated", "user", str(user_id), {"is_approved": body.is_approved}, request.client.host if request.client else None)
    await db.commit()
    return {"message": "User approval updated", "is_approved": user.is_approved}


@router.post("/admin/users/bulk-approval", dependencies=[admin_dependency])
async def bulk_approval(
    body: BulkApprovalRequest,
    request: Request,
    current_admin: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    if current_admin.id in body.user_ids and not body.is_approved:
        raise HTTPException(status_code=400, detail="You cannot block your own admin account")
    result = await db.execute(select(User).where(User.id.in_(body.user_ids)))
    users = list(result.scalars().all())
    if len(users) != len(set(body.user_ids)):
        raise HTTPException(status_code=404, detail="One or more users were not found")
    for user in users:
        user.is_approved = body.is_approved
        user.pending_approval = False
        db.add(Notification(user_id=user.id, title="Account Status Updated", message=f"Your account is now {'approved' if body.is_approved else 'blocked'} by an administrator.", type="info" if body.is_approved else "critical"))
    await log_audit_event(db, str(current_admin.id), "admin.users.bulk_approval", "users", None, {"user_ids": [str(item) for item in body.user_ids], "is_approved": body.is_approved, "reason": body.reason}, request.client.host if request.client else None)
    await db.commit()
    return {"message": "Bulk approval updated", "updated_count": len(users), "is_approved": body.is_approved}


@router.post("/admin/users/{user_id}/limit", dependencies=[admin_dependency])
async def update_user_limit(
    user_id: uuid.UUID,
    body: UserLimitRequest,
    request: Request,
    current_admin: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    user = await _get_user(db, user_id)
    user.scan_limit = body.scan_limit
    db.add(Notification(user_id=user.id, title="Scan Limit Updated", message=f"Your scan limit is now {body.scan_limit} scans.", type="info"))
    await log_audit_event(db, str(current_admin.id), "admin.user.limit_updated", "user", str(user_id), {"scan_limit": body.scan_limit}, request.client.host if request.client else None)
    await db.commit()
    return {"message": "User scan limit updated", "scan_limit": user.scan_limit}


@router.post("/admin/users/{user_id}/subscription", dependencies=[admin_dependency])
async def update_user_subscription(
    user_id: uuid.UUID,
    body: UserSubscriptionRequest,
    request: Request,
    current_admin: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    user = await _get_user(db, user_id)
    user.subscription_tier = body.subscription_tier
    user.subscription_status = body.subscription_status
    user.scan_limit = TIER_LIMITS[body.subscription_tier]
    db.add(Notification(user_id=user.id, title="Subscription Updated", message=f"Your plan is now {body.subscription_tier.upper()} ({body.subscription_status}).", type="info"))
    await log_audit_event(db, str(current_admin.id), "admin.user.subscription_updated", "user", str(user_id), body.model_dump(), request.client.host if request.client else None)
    await db.commit()
    return {"message": "Subscription updated", "subscription_tier": user.subscription_tier, "subscription_status": user.subscription_status, "scan_limit": user.scan_limit}


@router.get("/admin/findings", dependencies=[admin_dependency])
async def list_admin_findings(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=25, ge=1, le=100),
    status: FindingStatusValue | None = None,
    severity: str | None = Query(default=None, max_length=32),
    query: str = Query(default="", max_length=120),
    db: AsyncSession = Depends(get_db),
):
    filters = []
    if status:
        filters.append(Vulnerability.status == status)
    if severity:
        filters.append(Vulnerability.severity == severity)
    if query.strip():
        pattern = f"%{query.strip()}%"
        filters.append(or_(Vulnerability.description.ilike(pattern), Vulnerability.rule_id.ilike(pattern), Scan.target.ilike(pattern), User.email.ilike(pattern)))
    total = await db.scalar(select(func.count()).select_from(Vulnerability).join(Scan, Vulnerability.scan_id == Scan.id).join(User, Scan.user_id == User.id).where(*filters)) or 0
    result = await db.execute(
        select(Vulnerability, Scan, User.email)
        .join(Scan, Vulnerability.scan_id == Scan.id)
        .join(User, Scan.user_id == User.id)
        .where(*filters)
        .order_by(Vulnerability.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    return {"items": [_finding_payload(finding, scan, email) for finding, scan, email in result.all()], "total": total, "offset": offset, "limit": limit}


@router.patch("/admin/findings/{finding_id}", dependencies=[admin_dependency])
async def update_admin_finding(
    finding_id: uuid.UUID,
    body: FindingUpdateRequest,
    request: Request,
    current_admin: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Vulnerability, Scan).join(Scan, Vulnerability.scan_id == Scan.id).where(Vulnerability.id == finding_id))
    row = result.one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding, scan = row
    if body.status is not None and finding.status != body.status:
        db.add(FindingHistory(vulnerability_id=finding.id, user_id=current_admin.id, action="admin_status", from_value=finding.status, to_value=body.status))
        finding.status = body.status
    if body.clear_assignment or body.assigned_to_id is not None:
        assignee = None
        if body.assigned_to_id:
            assignee = await _get_user(db, body.assigned_to_id)
        previous = str(finding.assigned_to_id) if finding.assigned_to_id else None
        next_value = str(assignee.id) if assignee else None
        if previous != next_value:
            db.add(FindingHistory(vulnerability_id=finding.id, user_id=current_admin.id, action="admin_assignment", from_value=previous, to_value=next_value, details={"assignee": assignee.email if assignee else None}))
            finding.assigned_to_id = assignee.id if assignee else None
    if body.comment.strip():
        db.add(FindingComment(vulnerability_id=finding.id, user_id=current_admin.id, body=body.comment.strip()))
        db.add(FindingHistory(vulnerability_id=finding.id, user_id=current_admin.id, action="admin_comment", details={"body": body.comment.strip()[:200]}))
    await log_audit_event(db, str(current_admin.id), "admin.finding.updated", "finding", str(finding.id), {"status": finding.status, "assigned_to_id": str(finding.assigned_to_id) if finding.assigned_to_id else None, "comment_added": bool(body.comment.strip())}, request.client.host if request.client else None)
    await db.commit()
    owner_email = await db.scalar(select(User.email).where(User.id == scan.user_id))
    return _finding_payload(finding, scan, owner_email)


@router.post("/admin/communications", dependencies=[admin_dependency])
async def send_communication(
    body: CommunicationRequest,
    request: Request,
    current_admin: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    if body.user_id:
        recipients = [await _get_user(db, body.user_id)]
    else:
        recipients = list((await db.execute(select(User))).scalars().all())
    db.add_all([Notification(user_id=recipient.id, title=body.title, message=body.message, type=body.type) for recipient in recipients])
    audit_event = await log_audit_event(db, str(current_admin.id), "admin.communication_sent", "notification", str(body.user_id) if body.user_id else None, {"audience": "user" if body.user_id else "all_users", "type": body.type, "title": body.title, "message_preview": body.message[:160], "recipient_count": len(recipients), "email_requested": body.send_email, "email_status": "pending" if body.send_email else "not_requested"}, request.client.host if request.client else None)
    await db.commit()
    email_accepted_count = 0
    if body.send_email:
        for recipient in recipients:
            if queue_transactional_email(recipient.email, "admin_announcement", {"title": body.title, "message": body.message, "path": "/dashboard/notifications"}):
                email_accepted_count += 1
        audit_event.details = {**(audit_event.details or {}), "email_accepted_count": email_accepted_count, "email_status": "accepted" if email_accepted_count == len(recipients) else "partial" if email_accepted_count else "rejected"}
        await db.commit()
    return {"message": "Communication delivered", "recipient_count": len(recipients), "email_requested": body.send_email, "email_accepted_count": email_accepted_count}


@router.get("/admin/decision-queue", dependencies=[admin_dependency])
async def get_decision_queue(current_admin: User = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    workspace = await _get_workspace(db, current_admin)
    preferences = {**DEFAULT_WORKSPACE_SETTINGS["notification_preferences"], **(workspace.settings or {}).get("notification_preferences", {})}
    pending = await db.scalar(select(func.count()).select_from(User).where(User.pending_approval.is_(True))) or 0
    critical = await db.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.status == FindingStatus.OPEN.value, Vulnerability.severity == Severity.CRITICAL.value)) or 0
    high = await db.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.status == FindingStatus.OPEN.value, Vulnerability.severity == Severity.HIGH.value)) or 0
    failed = await db.scalar(select(func.count()).select_from(Scan).where(Scan.status == ScanStatus.FAILED.value, Scan.queued_at >= datetime.now(timezone.utc) - timedelta(hours=24))) or 0
    health = await integration_manager.health_check_all()
    unhealthy = [item.provider for item in health.values() if item.enabled and not item.healthy]
    items = []
    if pending and preferences.get("pending_approvals", True): items.append({"kind": "approvals", "count": pending, "priority": "medium", "label": "Accounts waiting for approval", "path": "/admin/users?filter=pending"})
    if critical and preferences.get("critical_findings", True): items.append({"kind": "critical_findings", "count": critical, "priority": "critical", "label": "Open critical findings", "path": "/admin/findings?severity=Critical&status=open"})
    if high and preferences.get("critical_findings", True): items.append({"kind": "high_findings", "count": high, "priority": "high", "label": "Open high findings", "path": "/admin/findings?severity=High&status=open"})
    if failed and preferences.get("failed_scan_spikes", True): items.append({"kind": "failed_scans", "count": failed, "priority": "high", "label": "Failed scans in the last 24 hours", "path": "/admin/scans?status=failed"})
    if unhealthy and preferences.get("provider_outages", True): items.append({"kind": "provider_outages", "count": len(unhealthy), "priority": "high", "label": "Providers need attention", "providers": unhealthy, "path": "/admin/operations"})
    await db.commit()
    return {"items": items, "updated_at": datetime.now(timezone.utc).isoformat()}


@router.get("/admin/workspace", dependencies=[admin_dependency])
async def get_admin_workspace(current_admin: User = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    workspace = await _get_workspace(db, current_admin)
    await db.commit()
    return {"settings": workspace.settings}


@router.patch("/admin/workspace", dependencies=[admin_dependency])
async def update_admin_workspace(body: WorkspaceUpdateRequest, request: Request, current_admin: User = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    workspace = await _get_workspace(db, current_admin)
    settings = deepcopy(workspace.settings or DEFAULT_WORKSPACE_SETTINGS)
    updates = body.model_dump(exclude_none=True)
    if "notification_preferences" in updates:
        settings["notification_preferences"] = {**settings.get("notification_preferences", {}), **updates["notification_preferences"]}
    if "saved_views" in updates:
        settings["saved_views"] = updates["saved_views"]
    if "templates" in updates:
        settings["templates"] = updates["templates"]
    workspace.settings = settings
    await log_audit_event(db, str(current_admin.id), "admin.workspace.updated", "admin_workspace", str(workspace.id), {"keys": list(updates)}, request.client.host if request.client else None)
    await db.commit()
    return {"settings": workspace.settings}


@router.post("/admin/workspace/saved-views", dependencies=[admin_dependency])
async def add_saved_view(body: SavedViewRequest, request: Request, current_admin: User = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    workspace = await _get_workspace(db, current_admin)
    settings = deepcopy(workspace.settings or DEFAULT_WORKSPACE_SETTINGS)
    views = list(settings.get("saved_views", []))
    view = {"id": str(uuid.uuid4()), **body.model_dump()}
    views.append(view)
    settings["saved_views"] = views[-50:]
    workspace.settings = settings
    await log_audit_event(db, str(current_admin.id), "admin.saved_view.created", "admin_workspace", str(workspace.id), {"view_id": view["id"], "name": body.name}, request.client.host if request.client else None)
    await db.commit()
    return view


@router.delete("/admin/workspace/saved-views/{view_id}", dependencies=[admin_dependency])
async def delete_saved_view(view_id: uuid.UUID, request: Request, current_admin: User = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    workspace = await _get_workspace(db, current_admin)
    settings = deepcopy(workspace.settings or DEFAULT_WORKSPACE_SETTINGS)
    before = list(settings.get("saved_views", []))
    settings["saved_views"] = [item for item in before if str(item.get("id")) != str(view_id)]
    if len(before) == len(settings["saved_views"]):
        raise HTTPException(status_code=404, detail="Saved view not found")
    workspace.settings = settings
    await log_audit_event(db, str(current_admin.id), "admin.saved_view.deleted", "admin_workspace", str(workspace.id), {"view_id": str(view_id)}, request.client.host if request.client else None)
    await db.commit()
    return {"message": "Saved view deleted"}


@router.get("/admin/audit-logs", dependencies=[admin_dependency])
async def list_audit_logs(
    limit: int = Query(default=50, ge=1, le=200),
    action: str = Query(default="", max_length=120),
    resource: str = Query(default="", max_length=64),
    db: AsyncSession = Depends(get_db),
):
    filters = []
    if action.strip():
        filters.append(AuditLog.action.ilike(f"%{action.strip()}%"))
    if resource.strip():
        filters.append(AuditLog.resource == resource.strip())
    result = await db.execute(
        select(AuditLog, User.email, User.name)
        .outerjoin(User, AuditLog.user_id == User.id)
        .where(*filters)
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
    )
    return [
        {
            "id": str(log.id), "action": log.action, "resource": log.resource,
            "resource_id": log.resource_id, "details": log.details or {}, "ip_address": log.ip_address,
            "actor": {"id": str(log.user_id) if log.user_id else None, "email": email, "name": name},
            "created_at": log.created_at.isoformat() if log.created_at else None,
        }
        for log, email, name in result.all()
    ]


@router.get("/admin/communications/history", dependencies=[admin_dependency])
async def communication_history(limit: int = Query(default=50, ge=1, le=200), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(AuditLog, User.email, User.name)
        .outerjoin(User, AuditLog.user_id == User.id)
        .where(AuditLog.action == "admin.communication_sent")
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
    )
    return [{"id": str(log.id), "actor": {"email": email, "name": name}, "details": log.details or {}, "created_at": log.created_at.isoformat() if log.created_at else None} for log, email, name in result.all()]


def _csv_response(rows: list[dict], filename: str) -> StreamingResponse:
    stream = io.StringIO()
    if rows:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return StreamingResponse(iter([stream.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/admin/export/users.csv", dependencies=[admin_dependency])
async def export_users(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    rows = [{"id": str(user.id), "email": user.email, "name": user.name, "role": user.role, "approved": user.is_approved, "subscription_tier": user.subscription_tier, "subscription_status": user.subscription_status, "scan_limit": user.scan_limit, "created_at": user.created_at.isoformat() if user.created_at else "", "last_login": user.last_login.isoformat() if user.last_login else ""} for user in result.scalars().all()]
    return _csv_response(rows, "vulnexus-users.csv")


@router.get("/admin/export/audit.csv", dependencies=[admin_dependency])
async def export_audit(limit: int = Query(default=1000, ge=1, le=10000), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AuditLog, User.email).outerjoin(User, AuditLog.user_id == User.id).order_by(AuditLog.created_at.desc()).limit(limit))
    rows = [{"id": str(log.id), "actor_email": email or "system", "action": log.action, "resource": log.resource, "resource_id": log.resource_id or "", "ip_address": log.ip_address or "", "details": log.details or {}, "created_at": log.created_at.isoformat() if log.created_at else ""} for log, email in result.all()]
    return _csv_response(rows, "vulnexus-audit.csv")


@router.get("/admin/analytics", dependencies=[admin_dependency])
async def get_admin_analytics(db: AsyncSession = Depends(get_db)):
    total_users = await db.scalar(select(func.count()).select_from(User)) or 0
    total_scans = await db.scalar(select(func.count()).select_from(Scan)) or 0
    completed_scans = await db.scalar(select(func.count()).select_from(Scan).where(Scan.status == ScanStatus.COMPLETED.value)) or 0
    failed_scans = await db.scalar(select(func.count()).select_from(Scan).where(Scan.status == ScanStatus.FAILED.value)) or 0
    active_threats = await db.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.status == FindingStatus.OPEN.value)) or 0
    queue_counts = {
        status.value: await db.scalar(select(func.count()).select_from(Scan).where(Scan.status == status.value)) or 0
        for status in (ScanStatus.QUEUED, ScanStatus.IN_PROGRESS, ScanStatus.FAILED)
    }
    tier_counts = {tier: await db.scalar(select(func.count()).select_from(User).where(User.subscription_tier == tier)) or 0 for tier in TIER_LIMITS}
    severity_breakdown = {severity.value: await db.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.status == FindingStatus.OPEN.value, Vulnerability.severity == severity.value)) or 0 for severity in Severity}

    recent_result = await db.execute(select(Scan, User.email).outerjoin(User, Scan.user_id == User.id).order_by(Scan.queued_at.desc()).limit(10))
    recent_scans = [{"scan_id": str(scan.id), "target": scan.target, "type": scan.type, "status": scan.status, "overall_score": scan.overall_score, "user_email": email or "Unknown", "queued_at": scan.queued_at.isoformat() if scan.queued_at else None} for scan, email in recent_result.all()]

    scan_trend = []
    for i in range(6, -1, -1):
        day = datetime.now(timezone.utc) - timedelta(days=i)
        start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
        end = start + timedelta(days=1)
        scan_trend.append({"date": day.strftime("%a"), "scans": await db.scalar(select(func.count()).select_from(Scan).where(Scan.queued_at >= start, Scan.queued_at < end)) or 0, "threats": await db.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.created_at >= start, Vulnerability.created_at < end, Vulnerability.status == FindingStatus.OPEN.value)) or 0})

    quota_result = await db.execute(select(User, func.count(Scan.id)).outerjoin(Scan, Scan.user_id == User.id).group_by(User.id))
    quota_alerts = []
    for user, scan_count in quota_result.all():
        limit_value = max(int(user.scan_limit or 0), 1)
        usage_percent = round((scan_count / limit_value) * 100, 1)
        if usage_percent >= 80:
            quota_alerts.append({"user_id": str(user.id), "email": user.email, "scan_count": scan_count, "scan_limit": user.scan_limit, "usage_percent": usage_percent})
    quota_alerts.sort(key=lambda item: item["usage_percent"], reverse=True)

    return {"total_users": total_users, "total_scans": total_scans, "completed_scans": completed_scans, "failed_scans": failed_scans, "active_threats": active_threats, "tier_counts": tier_counts, "severity_breakdown": severity_breakdown, "queue_counts": queue_counts, "recent_scans": recent_scans, "scan_trend": scan_trend, "quota_alerts": quota_alerts[:10]}


@router.get("/admin/providers/health", dependencies=[admin_dependency])
async def provider_health():
    health = await integration_manager.health_check_all()
    return [{"provider": item.provider, "enabled": item.enabled, "healthy": item.healthy, "message": item.message, "endpoint": item.endpoint, "checked_at": item.checked_at.isoformat(), "details": item.details} for item in health.values()]


@router.get("/admin/scans", dependencies=[admin_dependency])
async def list_admin_scans(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=25, ge=1, le=100),
    status: str | None = Query(default=None, max_length=32),
    db: AsyncSession = Depends(get_db),
):
    filters = [Scan.status == status] if status else []
    total = await db.scalar(select(func.count()).select_from(Scan).where(*filters)) or 0
    result = await db.execute(select(Scan, User.email).outerjoin(User, Scan.user_id == User.id).where(*filters).order_by(Scan.queued_at.desc()).offset(offset).limit(limit))
    return {"items": [{"id": str(scan.id), "target": scan.target, "type": scan.type, "status": scan.status, "error_message": scan.error_message, "user_email": email or "Unknown", "user_id": str(scan.user_id) if scan.user_id else None, "queued_at": scan.queued_at.isoformat() if scan.queued_at else None, "started_at": scan.started_at.isoformat() if scan.started_at else None, "finished_at": scan.finished_at.isoformat() if scan.finished_at else None} for scan, email in result.all()], "total": total, "offset": offset, "limit": limit}


@router.post("/admin/scans/{scan_id}/retry", dependencies=[admin_dependency])
async def retry_admin_scan(scan_id: uuid.UUID, request: Request, current_admin: User = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    original = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
    if not original:
        raise HTTPException(status_code=404, detail="Scan not found")
    if original.status not in {ScanStatus.FAILED.value, ScanStatus.CANCELED.value}:
        raise HTTPException(status_code=400, detail="Only failed or canceled scans can be retried")
    scan_file = None
    if original.type == ScanType.FILE.value:
        file_result = await db.execute(select(ScanFile).where(ScanFile.scan_id == original.id).limit(1))
        scan_file = file_result.scalar_one_or_none()
        if not scan_file:
            raise HTTPException(status_code=400, detail="Original uploaded file is no longer available")
    retry = Scan(type=original.type, target=original.target, status=ScanStatus.QUEUED.value, user_id=original.user_id, organization_id=original.organization_id, project_id=original.project_id, github_org=original.github_org, github_repo=original.github_repo, github_branch=original.github_branch, github_folder=original.github_folder)
    db.add(retry)
    await db.commit()
    await db.refresh(retry)
    if retry.type == ScanType.URL.value:
        from app.celery_app import run_url_scan_task
        run_url_scan_task.delay(str(retry.id), retry.target)
    elif retry.type == ScanType.GITHUB.value:
        from app.celery_app import run_github_scan_task
        run_github_scan_task.delay(str(retry.id), str(retry.user_id), retry.github_org or "", retry.github_repo or "", retry.github_branch or "main", retry.github_folder or "")
    else:
        from app.celery_app import run_file_scan_task
        run_file_scan_task.delay(str(retry.id), scan_file.path)
    await log_audit_event(db, str(current_admin.id), "admin.scan.retried", "scan", str(original.id), {"retry_scan_id": str(retry.id)}, request.client.host if request.client else None)
    await db.commit()
    return {"scan_id": str(retry.id), "status": retry.status}
