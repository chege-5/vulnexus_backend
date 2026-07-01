import secrets
import uuid
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import hash_password, verify_password, create_access_token, create_refresh_token, get_current_user, get_current_user_optional, decode_token_subject
from app.config import settings
from app.deps import get_db
from app.models.db_models import User, Notification, GitHubConnection
from app.services.oauth import (
    build_google_auth_url,
    build_github_auth_url,
    verify_google_token,
    exchange_google_code,
    exchange_github_code,
    oauth_login_or_register,
    get_github_connection_payload,
    sync_github_connection_metadata,
    disconnect_github_connection,
    list_github_branches,
)
from app.services.rbac import Permission, log_audit_event, require_permission
from app.utils.crypto import decrypt_token

router = APIRouter()


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: str
    phone: Optional[str] = ""
    carrier: Optional[str] = ""
    fav_programming_languages: Optional[List[str]] = None
    company: Optional[str] = ""
    job_role: Optional[str] = ""
    security_focus: Optional[str] = ""
    subscription_tier: Optional[str] = "free"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class OAuthRequest(BaseModel):
    id_token: Optional[str] = None
    code: Optional[str] = None
    state: Optional[str] = None
    redirect_uri: Optional[str] = None


class UpdateProfileRequest(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    company: Optional[str] = None
    job_role: Optional[str] = None
    security_focus: Optional[str] = None
    fav_programming_languages: Optional[List[str]] = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class SubscribeRequest(BaseModel):
    plan: Optional[str] = None
    tier: Optional[str] = None
    payment_method: Optional[str] = None
    mpesa_number: Optional[str] = None


class OAuthStartResponse(BaseModel):
    provider: str
    authorization_url: str
    state: str


class GitHubConnectionResponse(BaseModel):
    connected: bool
    github_username: Optional[str] = None
    github_user_id: Optional[str] = None
    connected_at: Optional[datetime] = None
    last_synced_at: Optional[datetime] = None
    organizations: list[dict] = Field(default_factory=list)
    repositories: list[dict] = Field(default_factory=list)
    branches: list[str] = Field(default_factory=list)
    permissions: dict[str, bool] = Field(default_factory=dict)


class GitHubBranchesResponse(BaseModel):
    owner: str
    repository: str
    branches: list[str] = Field(default_factory=list)


class UserSessionInfo(BaseModel):
    id: str
    email: str
    role: str
    name: str
    phone: str
    carrier: str
    fav_programming_languages: List[str] = []
    company: str
    job_role: str
    security_focus: str
    subscription_tier: str
    subscription_status: str
    scan_limit: int
    is_approved: bool
    avatar_url: Optional[str] = None
    auth_provider: str = "email"


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    user: UserSessionInfo


def _session_info(user: User) -> UserSessionInfo:
    return UserSessionInfo(
        id=str(user.id),
        email=user.email,
        role=user.role,
        name=user.name,
        phone=user.phone,
        carrier=user.carrier,
        fav_programming_languages=user.fav_programming_languages or [],
        company=user.company,
        job_role=user.job_role,
        security_focus=user.security_focus,
        subscription_tier=user.subscription_tier,
        subscription_status=user.subscription_status,
        scan_limit=user.scan_limit,
        is_approved=user.is_approved,
        avatar_url=user.avatar_url,
        auth_provider=user.auth_provider,
    )


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, db=Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")

    scan_limits = {
        "free": 10,
        "starter": 30,
        "developer": 100,
        "team": 500,
        "enterprise": 99999,
    }
    tier = (body.subscription_tier or "free").lower()
    limit = scan_limits.get(tier, 10)

    user = User(
        email=body.email,
        password_hash=hash_password(body.password),
        role="developer",
        name=body.name,
        phone=body.phone or "",
        carrier=body.carrier or "",
        fav_programming_languages=body.fav_programming_languages or [],
        company=body.company or "",
        job_role=body.job_role or "",
        security_focus=body.security_focus or "",
        subscription_tier=tier,
        subscription_status="active",
        scan_limit=limit,
        is_approved=True,
        pending_approval=False,
    )

    db.add(user)
    try:
        await db.commit()
        await db.refresh(user)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Email already registered")

    token = create_access_token({"sub": str(user.id)})
    refresh = create_refresh_token({"sub": str(user.id)})
    user.refresh_token = refresh
    await db.commit()
    return TokenResponse(access_token=token, refresh_token=refresh, user=_session_info(user))


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db=Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token({"sub": str(user.id)})
    refresh = create_refresh_token({"sub": str(user.id)})
    user.refresh_token = refresh
    user.last_login = datetime.utcnow()
    await db.commit()
    return TokenResponse(access_token=token, refresh_token=refresh, user=_session_info(user))


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(body: RefreshRequest, db=Depends(get_db)):
    """Refresh an access token using a refresh token."""
    try:
        payload = jwt.decode(body.refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    new_token = create_access_token({"sub": str(user.id)})
    new_refresh = create_refresh_token({"sub": str(user.id)})
    user.refresh_token = new_refresh
    await db.commit()
    return TokenResponse(access_token=new_token, refresh_token=new_refresh, user=_session_info(user))


@router.post("/google", response_model=TokenResponse)
async def google_auth(body: OAuthRequest, db=Depends(get_db)):
    """Authenticate with Google ID token."""
    if not settings.GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=501, detail="Google authentication not configured")
    
    if not body.id_token:
        raise HTTPException(status_code=400, detail="Google ID token is required")

    user_info = await verify_google_token(body.id_token)
    user, token = await oauth_login_or_register(
        db=db,
        provider="google",
        provider_user_id=user_info["provider_user_id"],
        email=user_info["email"],
        name=user_info["name"],
        avatar_url=user_info["avatar_url"],
    )
    refresh = create_refresh_token({"sub": str(user.id)})
    user.refresh_token = refresh
    await db.commit()
    return TokenResponse(access_token=token, refresh_token=refresh, user=_session_info(user))


@router.post("/github", response_model=TokenResponse)
async def github_auth(body: OAuthRequest, db=Depends(get_db)):
    """Authenticate with GitHub OAuth code."""
    if not settings.GITHUB_CLIENT_ID:
        raise HTTPException(status_code=501, detail="GitHub authentication not configured")
    
    if not body.code:
        raise HTTPException(status_code=400, detail="GitHub OAuth code is required")

    user_info = await exchange_github_code(body.code)
    user, token = await oauth_login_or_register(
        db=db,
        provider="github",
        provider_user_id=user_info["provider_user_id"],
        email=user_info["email"],
        name=user_info["name"],
        avatar_url=user_info["avatar_url"],
        access_token=user_info.get("access_token"),
        github_username=user_info.get("github_username"),
        metadata=user_info.get("metadata"),
    )
    refresh = create_refresh_token({"sub": str(user.id)})
    user.refresh_token = refresh
    await db.commit()
    return TokenResponse(access_token=token, refresh_token=refresh, user=_session_info(user))

@router.post("/subscribe")
@router.post("/subscribe-plan")
async def subscribe_plan(
    subscription: SubscribeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    plan = (subscription.plan or subscription.tier or "free").lower()

    plan_map = {
        "free": {"scan_limit": 10, "expires_in_days": None},
        "starter": {"scan_limit": 30, "expires_in_days": 30},
        "developer": {"scan_limit": 100, "expires_in_days": 30},
        "team": {"scan_limit": 500, "expires_in_days": 30},
        "enterprise": {"scan_limit": 99999, "expires_in_days": 30},
        "pro": {"scan_limit": 100, "expires_in_days": 30},
    }

    if plan == "pro":
        plan = "developer"

    if plan not in plan_map:
        raise HTTPException(
            status_code=400,
            detail="Invalid subscription plan."
        )

    plan_config = plan_map[plan]
    current_user.subscription_tier = plan
    current_user.subscription_status = "active"
    current_user.scan_limit = plan_config["scan_limit"]
    current_user.payment_method = subscription.payment_method or current_user.payment_method
    current_user.mpesa_number = subscription.mpesa_number or current_user.mpesa_number

    if plan == "free":
        current_user.subscription_expires_at = None
        current_user.trial_ends_at = None
    else:
        current_user.subscription_expires_at = datetime.utcnow() + timedelta(days=plan_config["expires_in_days"] or 30)
        current_user.trial_ends_at = None

    await db.commit()
    await db.refresh(current_user)

    return {
        "success": True,
        "message": f"Successfully subscribed to {plan.title()} plan.",
        "plan": current_user.subscription_tier,
        "scan_limit": current_user.scan_limit,
        "subscription_status": current_user.subscription_status,
        "subscription_expires_at": current_user.subscription_expires_at,
        "payment_method": current_user.payment_method,
        "mpesa_number": current_user.mpesa_number,
    }
    
    
@router.get("/google/start", response_model=OAuthStartResponse)
async def google_start(flow: str = "login"):
    state = f"google:{flow}:{secrets.token_urlsafe(16)}"
    return OAuthStartResponse(provider="google", authorization_url=build_google_auth_url(state), state=state)


@router.get("/github/start", response_model=OAuthStartResponse)
async def github_start(flow: str = "login"):
    state = f"github:{flow}:{secrets.token_urlsafe(16)}"
    return OAuthStartResponse(provider="github", authorization_url=build_github_auth_url(state), state=state)


@router.post("/google/exchange", response_model=TokenResponse)
async def google_exchange(body: OAuthRequest, db=Depends(get_db), current_user: Optional[User] = Depends(get_current_user_optional)):
    if not body.code:
        raise HTTPException(status_code=400, detail="Google OAuth code is required")

    user_info = await exchange_google_code(body.code, body.redirect_uri)
    user, token = await oauth_login_or_register(
        db=db,
        provider="google",
        provider_user_id=user_info["provider_user_id"],
        email=user_info["email"],
        name=user_info["name"],
        avatar_url=user_info["avatar_url"],
        access_token=user_info.get("access_token"),
        current_user=current_user,
    )
    refresh = create_refresh_token({"sub": str(user.id)})
    user.refresh_token = refresh
    await db.commit()
    return TokenResponse(access_token=token, refresh_token=refresh, user=_session_info(user))


@router.post("/github/exchange", response_model=TokenResponse)
async def github_exchange(body: OAuthRequest, db=Depends(get_db), current_user: Optional[User] = Depends(get_current_user_optional)):
    if not body.code:
        raise HTTPException(status_code=400, detail="GitHub OAuth code is required")

    user_info = await exchange_github_code(body.code, body.redirect_uri)
    user, token = await oauth_login_or_register(
        db=db,
        provider="github",
        provider_user_id=user_info["provider_user_id"],
        email=user_info["email"],
        name=user_info["name"],
        avatar_url=user_info["avatar_url"],
        access_token=user_info.get("access_token"),
        github_username=user_info.get("github_username"),
        metadata=user_info.get("metadata"),
        current_user=current_user,
    )
    refresh = create_refresh_token({"sub": str(user.id)})
    user.refresh_token = refresh
    await db.commit()
    return TokenResponse(access_token=token, refresh_token=refresh, user=_session_info(user))


@router.get("/github/connection", response_model=GitHubConnectionResponse)
async def github_connection(current_user: User = Depends(require_permission(Permission.GITHUB_CONNECT)), db=Depends(get_db)):
    payload = await get_github_connection_payload(db, current_user.id)
    return GitHubConnectionResponse(**payload)


@router.post("/github/connection/sync", response_model=GitHubConnectionResponse)
async def github_connection_sync(current_user: User = Depends(require_permission(Permission.GITHUB_SYNC)), db=Depends(get_db)):
    payload = await sync_github_connection_metadata(db, current_user.id)
    return GitHubConnectionResponse(**payload)


@router.delete("/github/connection")
async def github_connection_disconnect(current_user: User = Depends(require_permission(Permission.GITHUB_CONNECT)), db=Depends(get_db)):
    await disconnect_github_connection(db, current_user.id)
    await log_audit_event(db, str(current_user.id), "github.disconnect", "github_connection", str(current_user.id))
    return {"message": "GitHub account disconnected"}


@router.get("/github/repositories/{owner}/{repo}/branches", response_model=GitHubBranchesResponse)
async def github_repository_branches(owner: str, repo: str, current_user: User = Depends(require_permission(Permission.GITHUB_SCAN)), db=Depends(get_db)):
    payload = await get_github_connection_payload(db, current_user.id)
    if not payload.get("connected"):
        raise HTTPException(status_code=404, detail="GitHub account is not connected")

    result = await db.execute(select(GitHubConnection).where(GitHubConnection.user_id == current_user.id))
    connection = result.scalar_one_or_none()
    if not connection:
        raise HTTPException(status_code=404, detail="GitHub account is not connected")

    access_token = await decrypt_token(connection.access_token)
    branches = await list_github_branches(access_token, owner, repo)
    return GitHubBranchesResponse(owner=owner, repository=repo, branches=branches)


@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user), db=Depends(get_db)):
    """Logout by clearing refresh token."""
    result = await db.execute(select(User).where(User.id == current_user.id))
    user = result.scalar_one_or_none()
    if user:
        user.refresh_token = None
        await db.commit()
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserSessionInfo)
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current user info."""
    return _session_info(current_user)


@router.put("/me", response_model=UserSessionInfo)
async def update_me(
    body: UpdateProfileRequest,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """Update current user profile."""
    result = await db.execute(select(User).where(User.id == current_user.id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if body.name is not None:
        user.name = body.name
    if body.phone is not None:
        user.phone = body.phone
    if body.company is not None:
        user.company = body.company
    if body.job_role is not None:
        user.job_role = body.job_role
    if body.security_focus is not None:
        user.security_focus = body.security_focus
    if body.fav_programming_languages is not None:
        user.fav_programming_languages = body.fav_programming_languages
    
    await db.commit()
    return _session_info(user)


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """Change user password."""
    result = await db.execute(select(User).where(User.id == current_user.id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.password_hash:
        raise HTTPException(status_code=400, detail="OAuth users cannot change password")
    
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    user.password_hash = hash_password(body.new_password)
    await db.commit()
    return {"message": "Password changed successfully"}