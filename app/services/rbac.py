"""Role-Based Access Control system.

Centralized permission definitions and enforcement for the entire platform.
"""
from enum import Enum
from functools import wraps
from typing import Callable

from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.deps import get_db
from app.models.db_models import User


class Permission(str, Enum):
    # User management
    USER_READ = "user:read"
    USER_CREATE = "user:create"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    USER_APPROVE = "user:approve"
    
    # Scan operations
    SCAN_CREATE = "scan:create"
    SCAN_READ = "scan:read"
    SCAN_UPDATE = "scan:update"
    SCAN_DELETE = "scan:delete"
    SCAN_VIEW_ALL = "scan:view_all"
    
    # Vulnerability operations
    VULN_READ = "vuln:read"
    VULN_UPDATE = "vuln:update"  # change status
    VULN_DELETE = "vuln:delete"
    
    # Report operations
    REPORT_READ = "report:read"
    REPORT_CREATE = "report:create"
    REPORT_DELETE = "report:delete"
    
    # Dashboard
    DASHBOARD_READ = "dashboard:read"
    DASHBOARD_VIEW_ALL = "dashboard:view_all"
    
    # Admin operations
    ADMIN_ACCESS = "admin:access"
    ADMIN_ANALYTICS = "admin:analytics"
    ADMIN_SETTINGS = "admin:settings"
    ADMIN_COMMUNICATE = "admin:communicate"
    
    # GitHub operations
    GITHUB_CONNECT = "github:connect"
    GITHUB_SCAN = "github:scan"
    GITHUB_SYNC = "github:sync"
    
    # RBAC management
    RBAC_READ = "rbac:read"
    RBAC_WRITE = "rbac:write"
    
    # AI
    AI_QUERY = "ai:query"
    
    # Compliance
    COMPLIANCE_READ = "compliance:read"
    COMPLIANCE_REPORT = "compliance:report"
    
    # Notifications
    NOTIFICATION_READ = "notification:read"
    NOTIFICATION_SEND = "notification:send"
    
    # Organization management
    ORG_READ = "org:read"
    ORG_WRITE = "org:write"


# Role definitions with their permissions
ROLE_PERMISSIONS: dict[str, set[Permission]] = {
    "super_admin": {
        Permission.USER_READ, Permission.USER_CREATE, Permission.USER_UPDATE, Permission.USER_DELETE,
        Permission.USER_APPROVE,
        Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_UPDATE, Permission.SCAN_DELETE,
        Permission.SCAN_VIEW_ALL,
        Permission.VULN_READ, Permission.VULN_UPDATE, Permission.VULN_DELETE,
        Permission.REPORT_READ, Permission.REPORT_CREATE, Permission.REPORT_DELETE,
        Permission.DASHBOARD_READ, Permission.DASHBOARD_VIEW_ALL,
        Permission.ADMIN_ACCESS, Permission.ADMIN_ANALYTICS, Permission.ADMIN_SETTINGS,
        Permission.ADMIN_COMMUNICATE,
        Permission.GITHUB_CONNECT, Permission.GITHUB_SCAN, Permission.GITHUB_SYNC,
        Permission.RBAC_READ, Permission.RBAC_WRITE,
        Permission.AI_QUERY,
        Permission.COMPLIANCE_READ, Permission.COMPLIANCE_REPORT,
        Permission.NOTIFICATION_READ, Permission.NOTIFICATION_SEND,
        Permission.ORG_READ, Permission.ORG_WRITE,
    },
    "admin": {
        Permission.USER_READ, Permission.USER_CREATE, Permission.USER_UPDATE,
        Permission.USER_APPROVE,
        Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_UPDATE,
        Permission.SCAN_VIEW_ALL,
        Permission.VULN_READ, Permission.VULN_UPDATE,
        Permission.REPORT_READ, Permission.REPORT_CREATE,
        Permission.DASHBOARD_READ, Permission.DASHBOARD_VIEW_ALL,
        Permission.ADMIN_ACCESS, Permission.ADMIN_ANALYTICS, Permission.ADMIN_SETTINGS,
        Permission.ADMIN_COMMUNICATE,
        Permission.GITHUB_CONNECT, Permission.GITHUB_SCAN, Permission.GITHUB_SYNC,
        Permission.RBAC_READ,
        Permission.AI_QUERY,
        Permission.COMPLIANCE_READ, Permission.COMPLIANCE_REPORT,
        Permission.NOTIFICATION_READ, Permission.NOTIFICATION_SEND,
        Permission.ORG_READ,
    },
    "security_analyst": {
        Permission.USER_READ,
        Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_UPDATE,
        Permission.SCAN_VIEW_ALL,
        Permission.VULN_READ, Permission.VULN_UPDATE,
        Permission.REPORT_READ, Permission.REPORT_CREATE,
        Permission.DASHBOARD_READ, Permission.DASHBOARD_VIEW_ALL,
        Permission.GITHUB_CONNECT, Permission.GITHUB_SCAN, Permission.GITHUB_SYNC,
        Permission.AI_QUERY,
        Permission.COMPLIANCE_READ, Permission.COMPLIANCE_REPORT,
        Permission.NOTIFICATION_READ,
        Permission.ORG_READ, Permission.ORG_WRITE,
    },
    "qa_engineer": {
        Permission.SCAN_CREATE, Permission.SCAN_READ,
        Permission.VULN_READ, Permission.VULN_UPDATE,
        Permission.REPORT_READ,
        Permission.DASHBOARD_READ,
        Permission.GITHUB_CONNECT, Permission.GITHUB_SCAN,
        Permission.AI_QUERY,
        Permission.NOTIFICATION_READ,
        Permission.ORG_READ, Permission.ORG_WRITE,
    },
    "developer": {
        Permission.SCAN_CREATE, Permission.SCAN_READ,
        Permission.VULN_READ,
        Permission.REPORT_READ,
        Permission.DASHBOARD_READ,
        Permission.GITHUB_CONNECT, Permission.GITHUB_SCAN,
        Permission.AI_QUERY,
        Permission.NOTIFICATION_READ,
        Permission.ORG_READ, Permission.ORG_WRITE,
    },
    "tester": {
        Permission.SCAN_CREATE, Permission.SCAN_READ,
        Permission.VULN_READ, Permission.VULN_UPDATE,
        Permission.REPORT_READ,
        Permission.DASHBOARD_READ,
        Permission.GITHUB_CONNECT, Permission.GITHUB_SCAN,
        Permission.AI_QUERY,
        Permission.NOTIFICATION_READ,
        Permission.ORG_READ, Permission.ORG_WRITE,
    },
    "viewer": {
        Permission.SCAN_READ,
        Permission.VULN_READ,
        Permission.REPORT_READ,
        Permission.DASHBOARD_READ,
        Permission.AI_QUERY,
        Permission.NOTIFICATION_READ,
    },
}


def has_permission(user: User, required_permission: Permission) -> bool:
    """Check if user has a specific permission."""
    if user.role in ROLE_PERMISSIONS:
        return required_permission in ROLE_PERMISSIONS[user.role]
    return False


def require_permission(required_permission: Permission):
    """Dependency factory that checks for a required permission."""
    async def permission_dependency(
        current_user: User = Depends(get_current_user),
    ):
        if not has_permission(current_user, required_permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {required_permission.value}",
            )
        return current_user
    return permission_dependency


def require_any_permission(*permissions: Permission):
    """Dependency factory that checks if user has ANY of the required permissions."""
    async def permission_dependency(
        current_user: User = Depends(get_current_user),
    ):
        for perm in permissions:
            if has_permission(current_user, perm):
                return current_user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions for this operation",
        )
    return permission_dependency


async def require_admin(user: User = Depends(get_current_user)) -> User:
    """Legacy helper - checks if user is admin or super_admin."""
    if user.role not in ("admin", "super_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user


async def log_audit_event(
    db: AsyncSession,
    user_id: str,
    action: str,
    resource: str,
    resource_id: str = None,
    details: dict = None,
    ip_address: str = None,
):
    """Log an audit event."""
    from app.models.db_models import AuditLog
    import uuid
    
    log = AuditLog(
        user_id=uuid.UUID(user_id) if user_id else None,
        action=action,
        resource=resource,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address,
    )
    db.add(log)
