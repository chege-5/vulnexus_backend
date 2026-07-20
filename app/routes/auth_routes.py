import secrets
import uuid
import hmac
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr, Field
from jose import JWTError, jwt
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import hash_password, verify_password, create_access_token, create_refresh_token, get_current_user, get_current_user_optional, decode_token_subject, validate_password_strength, hash_token
from app.config import settings
from app.deps import get_db
from app.rate_limit import limiter
from app.models.db_models import AuthSession, User, Notification, GitHubConnection
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
from app.services.email import notification_email_enabled, queue_transactional_email, send_email_verification, send_password_reset_email
from app.services.mfa import consume_recovery_code, generate_recovery_codes, generate_totp_secret, provisioning_uri, verify_totp
from app.services.rbac import Permission, log_audit_event, require_permission
from app.services.oauth_transactions import create_oauth_transaction, consume_oauth_transaction, pkce_challenge
from app.utils.logger import get_logger

router = APIRouter()
logger = get_logger(__name__)

OAUTH_ALLOWED_FLOWS = {"login", "signup", "link"}


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
    refresh_token: Optional[str] = None


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


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    code: str = Field(pattern=r"^\d{6}$")
    new_password: str


class VerifyResetCodeRequest(BaseModel):
    email: EmailStr
    code: str = Field(pattern=r"^\d{6}$")


class VerifyEmailRequest(BaseModel):
    email: EmailStr
    code: str = Field(pattern=r"^\d{6}$")


class ResendVerificationRequest(BaseModel):
    email: EmailStr


class EmailPreferencesRequest(BaseModel):
    preferences: dict[str, bool]


class MFAEnableRequest(BaseModel):
    code: str


class MFALoginVerifyRequest(BaseModel):
    challenge_token: str
    code: Optional[str] = None
    recovery_code: Optional[str] = None


class MFADisableRequest(BaseModel):
    password: str
    code: Optional[str] = None
    recovery_code: Optional[str] = None


class MFARegenerateRecoveryRequest(BaseModel):
    password: str
    code: str


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
    fav_programming_languages: List[str] = Field(default_factory=list)
    company: str
    job_role: str
    security_focus: str
    subscription_tier: str
    subscription_status: str
    scan_limit: int
    is_approved: bool
    avatar_url: Optional[str] = None
    auth_provider: str = "email"
    email_verified: bool = False
    mfa_enabled: bool = False


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    user: UserSessionInfo


class MFAChallengeResponse(BaseModel):
    mfa_required: bool = True
    challenge_token: str
    expires_in_seconds: int
    delivery: str = "totp"


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
        email_verified=bool(user.email_verified),
        mfa_enabled=bool(user.mfa_enabled),
    )


def _require_oauth_config(provider: str) -> None:
    if provider == "google" and (not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET):
        raise HTTPException(status_code=501, detail="Google OAuth is not configured")
    if provider == "github" and (not settings.GITHUB_CLIENT_ID or not settings.GITHUB_CLIENT_SECRET):
        raise HTTPException(status_code=501, detail="GitHub OAuth is not configured")


def _as_aware_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


async def _decrypt_access_token(encrypted_token: str) -> str:
    from app.utils.crypto import decrypt_token

    try:
        return await decrypt_token(encrypted_token)
    except Exception:
        return encrypted_token


async def _store_refresh(user: User, db: AsyncSession, *, family_id: str | None = None, replaced_session: AuthSession | None = None) -> str:
    session_id = str(uuid.uuid4())
    family_id = family_id or uuid.uuid4().hex
    refresh = create_refresh_token({"sub": str(user.id), "sid": session_id, "family": family_id})
    user.refresh_token = hash_token(refresh)
    session = AuthSession(
        id=uuid.UUID(session_id), user_id=user.id, family_id=family_id,
        token_hash=hash_token(refresh),
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(session)
    await db.flush()
    if replaced_session:
        replaced_session.revoked_at = datetime.now(timezone.utc)
        replaced_session.replaced_by_id = session.id
    return refresh


async def _issue_session(user: User, response: Response, db: AsyncSession) -> TokenResponse:
    token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh = await _store_refresh(user, db)
    _set_refresh_cookie(response, refresh)
    return TokenResponse(access_token=token, user=_session_info(user))


def _create_mfa_challenge(user: User) -> MFAChallengeResponse:
    challenge = secrets.token_urlsafe(32)
    user.mfa_challenge_token_hash = hash_token(challenge)
    user.mfa_challenge_expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.MFA_CHALLENGE_EXPIRE_MINUTES)
    return MFAChallengeResponse(
        challenge_token=challenge,
        expires_in_seconds=settings.MFA_CHALLENGE_EXPIRE_MINUTES * 60,
    )


def _verification_required(user: User) -> bool:
    return settings.EMAIL_ENABLED and settings.REQUIRE_EMAIL_VERIFICATION and user.auth_provider == "email" and not user.email_verified


async def _send_verification_for_user(user: User, db) -> str:
    now = datetime.now(timezone.utc)
    last_sent = _as_aware_utc(user.email_verification_sent_at)
    if last_sent and (now - last_sent).total_seconds() < settings.EMAIL_VERIFICATION_COOLDOWN_SECONDS:
        return ""
    code = f"{secrets.randbelow(1_000_000):06d}"
    user.email_verification_token_hash = hash_token(code)
    user.email_verification_expires_at = now + timedelta(hours=24)
    user.email_verification_sent_at = now
    await db.commit()
    try:
        await send_email_verification(user.email, code)
    except Exception:
        logger.exception("Email verification delivery failed")
    return code


async def _send_welcome_email_if_needed(user: User, db) -> bool:
    """Record a welcome email only after Resend accepts it, allowing a later login to retry."""
    if user.welcome_email_sent_at is not None:
        return False
    if not queue_transactional_email(user.email, "welcome", {"name": user.name}):
        return False
    user.welcome_email_sent_at = datetime.now(timezone.utc)
    await db.commit()
    return True


def _set_refresh_cookie(response: Response, refresh_token: str) -> None:
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=refresh_token,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite=settings.SESSION_COOKIE_SAMESITE,
        domain=settings.SESSION_COOKIE_DOMAIN,
        path="/",
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        domain=settings.SESSION_COOKIE_DOMAIN,
        path="/",
    )


async def _user_from_refresh_cookie(request: Request, db: AsyncSession) -> User | None:
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not token:
        return None
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "refresh":
            return None
        user_id = uuid.UUID(payload["sub"])
        session_id = uuid.UUID(payload["sid"])
    except (JWTError, ValueError, KeyError, TypeError):
        return None
    result = await db.execute(select(AuthSession).where(AuthSession.id == session_id, AuthSession.token_hash == hash_token(token)))
    auth_session = result.scalar_one_or_none()
    if not auth_session or auth_session.revoked_at or _as_aware_utc(auth_session.expires_at) < datetime.now(timezone.utc):
        return None
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, response: Response, db=Depends(get_db)):
    validate_password_strength(body.password)
    normalized_email = body.email.lower()
    result = await db.execute(select(User).where(User.email == normalized_email))
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
        email=normalized_email,
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
        email_verified=not (settings.EMAIL_ENABLED and settings.REQUIRE_EMAIL_VERIFICATION),
    )

    db.add(user)
    try:
        await db.commit()
        await db.refresh(user)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Email already registered")

    if not user.email_verified:
        await _send_verification_for_user(user, db)
    session = await _issue_session(user, response, db)
    await db.commit()
    return session


@router.post("/login")
async def login(body: LoginRequest, response: Response, db=Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email.lower()))
    user = result.scalar_one_or_none()
    if not user or not user.password_hash or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_approved or user.pending_approval:
        raise HTTPException(status_code=403, detail="Account is pending approval")
    if _verification_required(user):
        raise HTTPException(status_code=403, detail="Email verification is required before login")
    if user.mfa_enabled:
        challenge = _create_mfa_challenge(user)
        await db.commit()
        return challenge

    user.last_login = datetime.now(timezone.utc)
    session = await _issue_session(user, response, db)
    await db.commit()
    await _send_welcome_email_if_needed(user, db)
    return session


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(body: RefreshRequest, request: Request, response: Response, db=Depends(get_db)):
    """Refresh an access token using a refresh token."""
    provided_refresh = body.refresh_token or request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not provided_refresh:
        raise HTTPException(status_code=401, detail="Refresh session is required")
    try:
        payload = jwt.decode(provided_refresh, settings.JWT_SECRET, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        parsed_user_id = uuid.UUID(user_id)
    except (JWTError, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    result = await db.execute(select(User).where(User.id == parsed_user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if _verification_required(user):
        raise HTTPException(status_code=403, detail="Email verification is required before login")
    session_id = payload.get("sid")
    if not session_id:
        # One release of legacy tokens may be refreshed once; every successor is tracked per-session.
        if not user.refresh_token or not hmac.compare_digest(user.refresh_token, hash_token(provided_refresh)):
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        auth_session = None
    else:
        try:
            parsed_session_id = uuid.UUID(session_id)
        except (ValueError, TypeError):
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        result = await db.execute(select(AuthSession).where(AuthSession.id == parsed_session_id, AuthSession.token_hash == hash_token(provided_refresh)))
        auth_session = result.scalar_one_or_none()
        if not auth_session:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        if auth_session.revoked_at:
            await db.execute(update(AuthSession).where(AuthSession.family_id == auth_session.family_id, AuthSession.revoked_at.is_(None)).values(revoked_at=datetime.now(timezone.utc)))
            await db.commit()
            _clear_refresh_cookie(response)
            logger.warning("Refresh token reuse detected: user_id=%s family_id=%s", user.id, auth_session.family_id)
            raise HTTPException(status_code=401, detail="Refresh session has been revoked")
        if _as_aware_utc(auth_session.expires_at) < datetime.now(timezone.utc):
            auth_session.revoked_at = datetime.now(timezone.utc)
            await db.commit()
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    if not auth_session and (not user.refresh_token or not hmac.compare_digest(user.refresh_token, hash_token(provided_refresh))):
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    new_token = create_access_token({"sub": str(user.id), "role": user.role})
    new_refresh = await _store_refresh(user, db, family_id=auth_session.family_id if auth_session else None, replaced_session=auth_session)
    await db.commit()
    _set_refresh_cookie(response, new_refresh)
    return TokenResponse(access_token=new_token, user=_session_info(user))


@router.post("/google", response_model=TokenResponse)
async def google_auth(body: OAuthRequest, response: Response, db=Depends(get_db)):
    """Retired: provider credentials and authorization codes never enter the frontend."""
    raise HTTPException(status_code=410, detail="Use /auth/google/login for the server-side OAuth flow")


@router.post("/github", response_model=TokenResponse)
async def github_auth(body: OAuthRequest, response: Response, db=Depends(get_db)):
    """Retired: provider credentials and authorization codes never enter the frontend."""
    raise HTTPException(status_code=410, detail="Use /auth/github/login for the server-side OAuth flow")

@router.post("/subscribe")
@router.post("/subscribe-plan")
async def subscribe_plan(
    subscription: SubscribeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    plan = (subscription.plan or subscription.tier or "free").lower()
    previous_plan = current_user.subscription_tier
    previous_status = current_user.subscription_status

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
        current_user.subscription_expires_at = datetime.now(timezone.utc) + timedelta(days=plan_config["expires_in_days"] or 30)
        current_user.trial_ends_at = None

    await db.commit()
    await db.refresh(current_user)
    if (previous_plan != current_user.subscription_tier or previous_status != current_user.subscription_status) and notification_email_enabled(current_user.email_preferences, "subscription"):
        queue_transactional_email(
            current_user.email,
            "subscription",
            {"name": current_user.name, "status": current_user.subscription_status, "path": "/dashboard/billing"},
        )

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
    
    
def _frontend_oauth_redirect(provider: str, outcome: str, reason: str | None = None) -> RedirectResponse:
    frontend = settings.FRONTEND_URL or next((origin.strip() for origin in settings.CORS_ORIGINS.split(",") if origin.strip()), "http://localhost:5173")
    query = {"oauth": outcome, "provider": provider}
    if reason:
        query["reason"] = reason
    return RedirectResponse(f"{frontend.rstrip('/')}/auth/callback?{urlencode(query)}", status_code=status.HTTP_303_SEE_OTHER)


async def _oauth_login_redirect(provider: str, request: Request, db: AsyncSession, flow: str) -> RedirectResponse:
    if flow not in OAUTH_ALLOWED_FLOWS:
        raise HTTPException(status_code=400, detail="Invalid OAuth flow")
    _require_oauth_config(provider)
    link_user_id = None
    if flow == "link":
        current_user = await _user_from_refresh_cookie(request, db)
        if not current_user:
            raise HTTPException(status_code=401, detail="Sign in before linking an OAuth account")
        link_user_id = str(current_user.id)
    state, verifier = await create_oauth_transaction(provider, flow, link_user_id=link_user_id)
    redirect_uri = settings.GOOGLE_REDIRECT_URI if provider == "google" else settings.GITHUB_REDIRECT_URI
    authorization_url = (
        build_google_auth_url(state, redirect_uri, pkce_challenge(verifier))
        if provider == "google" else build_github_auth_url(
            state, redirect_uri,
            settings.GITHUB_INTEGRATION_SCOPE if flow == "link" else settings.GITHUB_OAUTH_SCOPE,
        )
    )
    # The callback URL is deliberately safe to log.  It is the configured
    # backend endpoint, not a token, authorization code, cookie, or state.
    logger.info(
        "OAuth authorization started: provider=%s flow=%s link=%s redirect_uri=%s",
        provider, flow, bool(link_user_id), redirect_uri,
    )
    return RedirectResponse(authorization_url, status_code=status.HTTP_302_FOUND)


@router.get("/google/login")
@limiter.limit("20/hour")
async def google_login(request: Request, db=Depends(get_db), flow: str = "login"):
    return await _oauth_login_redirect("google", request, db, flow)


@router.get("/github/login")
@limiter.limit("20/hour")
async def github_login(request: Request, db=Depends(get_db), flow: str = "login"):
    return await _oauth_login_redirect("github", request, db, flow)


async def _oauth_callback(provider: str, code: str | None, state: str | None, provider_error: str | None, db: AsyncSession) -> RedirectResponse:
    if provider_error:
        logger.info("OAuth provider cancelled or denied authorization: provider=%s", provider)
        return _frontend_oauth_redirect(provider, "error", "provider_denied")
    if not code:
        return _frontend_oauth_redirect(provider, "error", "missing_code")
    try:
        transaction = await consume_oauth_transaction(provider, state)
        if provider == "google":
            identity = await exchange_google_code(code, settings.GOOGLE_REDIRECT_URI, transaction["pkce_verifier"])
        else:
            identity = await exchange_github_code(code, settings.GITHUB_REDIRECT_URI)
        link_user = None
        if transaction.get("link_user_id"):
            result = await db.execute(select(User).where(User.id == uuid.UUID(transaction["link_user_id"])))
            link_user = result.scalar_one_or_none()
            if not link_user:
                raise HTTPException(status_code=401, detail="The linking session is no longer valid")
        user, _ = await oauth_login_or_register(
            db=db, provider=provider, provider_user_id=identity["provider_user_id"], email=identity["email"],
            name=identity["name"], avatar_url=identity["avatar_url"], access_token=identity.get("access_token"),
            refresh_token=identity.get("refresh_token"), github_username=identity.get("github_username"),
            metadata=identity.get("metadata"), current_user=link_user,
            provider_email_verified=bool(identity.get("email_verified")),
        )
        response = _frontend_oauth_redirect(provider, "success")
        await _issue_session(user, response, db)
        await db.commit()
        logger.info("OAuth callback completed: provider=%s user_id=%s flow=%s", provider, user.id, transaction["flow"])
        return response
    except HTTPException as exc:
        logger.warning("OAuth callback rejected: provider=%s status=%s", provider, exc.status_code)
        return _frontend_oauth_redirect(provider, "error", "state_expired" if "state" in str(exc.detail).lower() else "provider_exchange_failed")
    except Exception:
        logger.exception("OAuth callback failed: provider=%s", provider)
        return _frontend_oauth_redirect(provider, "error", "unexpected")


@router.get("/google/callback")
@limiter.limit("20/hour")
async def google_callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None, db=Depends(get_db)):
    return await _oauth_callback("google", code, state, error, db)


@router.get("/github/callback")
@limiter.limit("20/hour")
async def github_callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None, db=Depends(get_db)):
    return await _oauth_callback("github", code, state, error, db)


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

    access_token = await _decrypt_access_token(connection.access_token)
    branches = await list_github_branches(access_token, owner, repo)
    return GitHubBranchesResponse(owner=owner, repository=repo, branches=branches)


@router.post("/logout")
async def logout(response: Response, current_user: User = Depends(get_current_user), db=Depends(get_db)):
    """Logout by clearing refresh token."""
    result = await db.execute(select(User).where(User.id == current_user.id))
    user = result.scalar_one_or_none()
    if user:
        user.refresh_token = None
        await db.execute(update(AuthSession).where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None)).values(revoked_at=datetime.now(timezone.utc)))
        await db.commit()
    _clear_refresh_cookie(response)
    return {"message": "Logged out successfully"}


@router.post("/forgot-password")
@limiter.limit("5/hour")
async def forgot_password(request: Request, body: ForgotPasswordRequest, db=Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email.lower()))
    user = result.scalar_one_or_none()
    if user:
        code = f"{secrets.randbelow(1_000_000):06d}"
        user.password_reset_token_hash = hash_token(code)
        user.password_reset_expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)
        await db.commit()
        try:
            await send_password_reset_email(user.email, code)
        except Exception:
            logger.exception("Password reset email delivery failed")
    return {"message": "If the account exists, a six-digit reset code has been sent."}


@router.post("/validate-reset-code")
@limiter.limit("10/hour")
async def validate_reset_code(request: Request, body: VerifyResetCodeRequest, db=Depends(get_db)):
    code_hash = hash_token(body.code)
    result = await db.execute(
        select(User).where(
            User.email == body.email.lower(),
            User.password_reset_token_hash == code_hash,
        )
    )
    user = result.scalar_one_or_none()
    expires_at = _as_aware_utc(user.password_reset_expires_at if user else None)
    if not user or not expires_at or expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired reset code")
    return {"message": "Reset code verified"}


@router.post("/reset-password")
@limiter.limit("10/hour")
async def reset_password(request: Request, response: Response, body: ResetPasswordRequest, db=Depends(get_db)):
    validate_password_strength(body.new_password)
    code_hash = hash_token(body.code)
    result = await db.execute(
        select(User).where(
            User.email == body.email.lower(),
            User.password_reset_token_hash == code_hash,
        )
    )
    user = result.scalar_one_or_none()
    expires_at = _as_aware_utc(user.password_reset_expires_at if user else None)
    if not user or not expires_at or expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired reset code")
    user.password_hash = hash_password(body.new_password)
    user.password_reset_token_hash = None
    user.password_reset_expires_at = None
    session = await _issue_session(user, response, db)
    await db.commit()
    queue_transactional_email(user.email, "password_changed", {"name": user.name})
    return session


@router.post("/verify-email")
@limiter.limit("10/hour")
async def verify_email(request: Request, response: Response, body: VerifyEmailRequest, db=Depends(get_db)):
    code_hash = hash_token(body.code)
    result = await db.execute(
        select(User).where(
            User.email == body.email.lower(),
            User.email_verification_token_hash == code_hash,
        )
    )
    user = result.scalar_one_or_none()
    expires_at = _as_aware_utc(user.email_verification_expires_at if user else None)
    if not user or not expires_at or expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired verification code")
    user.email_verified = True
    user.email_verification_token_hash = None
    user.email_verification_expires_at = None
    session = await _issue_session(user, response, db)
    await db.commit()
    await _send_welcome_email_if_needed(user, db)
    return session


@router.post("/resend-verification")
@limiter.limit("5/hour")
async def resend_verification(request: Request, body: ResendVerificationRequest, db=Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email.lower()))
    user = result.scalar_one_or_none()
    if user and not user.email_verified:
        await _send_verification_for_user(user, db)
    return {"message": "If verification is required, a verification email has been sent."}


@router.get("/email-preferences")
async def get_email_preferences(current_user: User = Depends(get_current_user)):
    return {"preferences": current_user.email_preferences or {}}


@router.patch("/email-preferences")
async def update_email_preferences(body: EmailPreferencesRequest, db=Depends(get_db), current_user: User = Depends(get_current_user)):
    allowed = {"scan_completed", "scan_failed", "critical_finding", "report_ready", "subscription", "team_invitation"}
    current_user.email_preferences = {
        **(current_user.email_preferences or {}),
        **{key: bool(value) for key, value in body.preferences.items() if key in allowed},
    }
    await db.commit()
    return {"preferences": current_user.email_preferences}


@router.get("/mfa/status")
async def mfa_status(current_user: User = Depends(get_current_user)):
    return {
        "enabled": bool(current_user.mfa_enabled),
        "recovery_codes_remaining": len(current_user.mfa_recovery_codes or []),
    }


@router.post("/mfa/setup")
@limiter.limit("5/hour")
async def mfa_setup(
    request: Request,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == current_user.id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is already enabled")
    secret = generate_totp_secret()
    user.mfa_secret = secret
    await db.commit()
    return {
        "secret": secret,
        "manual_key": secret,
        "otpauth_url": provisioning_uri(secret=secret, account_name=user.email),
        "issuer": settings.MFA_ISSUER,
    }


@router.post("/mfa/enable")
@limiter.limit("10/hour")
async def mfa_enable(
    body: MFAEnableRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == current_user.id))
    user = result.scalar_one_or_none()
    if not user or not user.mfa_secret:
        raise HTTPException(status_code=400, detail="Start MFA setup first")
    if not verify_totp(user.mfa_secret, body.code):
        raise HTTPException(status_code=400, detail="Invalid MFA code")
    recovery_codes, recovery_hashes = generate_recovery_codes()
    user.mfa_enabled = True
    user.mfa_recovery_codes = recovery_hashes
    await db.commit()
    return {"message": "MFA enabled", "recovery_codes": recovery_codes}


@router.post("/mfa/verify-login", response_model=TokenResponse)
@limiter.limit("20/hour")
async def mfa_verify_login(body: MFALoginVerifyRequest, request: Request, response: Response, db=Depends(get_db)):
    challenge_hash = hash_token(body.challenge_token)
    result = await db.execute(select(User).where(User.mfa_challenge_token_hash == challenge_hash))
    user = result.scalar_one_or_none()
    expires_at = _as_aware_utc(user.mfa_challenge_expires_at if user else None)
    if not user or not expires_at or expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Invalid or expired MFA challenge")

    verified = verify_totp(user.mfa_secret, body.code or "")
    if not verified and body.recovery_code:
        verified, remaining = consume_recovery_code(user.mfa_recovery_codes, body.recovery_code)
        if verified:
            user.mfa_recovery_codes = remaining
    if not verified:
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    user.mfa_challenge_token_hash = None
    user.mfa_challenge_expires_at = None
    user.last_login = datetime.now(timezone.utc)
    session = await _issue_session(user, response, db)
    await db.commit()
    return session


@router.post("/mfa/disable")
@limiter.limit("10/hour")
async def mfa_disable(
    body: MFADisableRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == current_user.id))
    user = result.scalar_one_or_none()
    if not user or not user.password_hash or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")
    verified = verify_totp(user.mfa_secret, body.code or "")
    if not verified and body.recovery_code:
        verified, remaining = consume_recovery_code(user.mfa_recovery_codes, body.recovery_code)
        if verified:
            user.mfa_recovery_codes = remaining
    if not verified:
        raise HTTPException(status_code=401, detail="Invalid MFA code")
    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_recovery_codes = []
    await db.commit()
    return {"message": "MFA disabled"}


@router.post("/mfa/recovery-codes/regenerate")
@limiter.limit("5/hour")
async def mfa_regenerate_recovery_codes(
    body: MFARegenerateRecoveryRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == current_user.id))
    user = result.scalar_one_or_none()
    if not user or not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")
    if not user.password_hash or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")
    if not verify_totp(user.mfa_secret, body.code):
        raise HTTPException(status_code=401, detail="Invalid MFA code")
    recovery_codes, recovery_hashes = generate_recovery_codes()
    user.mfa_recovery_codes = recovery_hashes
    await db.commit()
    return {"recovery_codes": recovery_codes}


@router.get("/me", response_model=UserSessionInfo)
async def get_me(request: Request, response: Response, db=Depends(get_db), current_user: Optional[User] = Depends(get_current_user_optional)):
    """Get the current user from a bearer token or the HttpOnly refresh session.

    The OAuth completion page uses this route once after the backend callback;
    it never receives or exchanges a provider authorization code.
    """
    user = current_user or await _user_from_refresh_cookie(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication is required")
    response.headers["X-Access-Token"] = create_access_token({"sub": str(user.id), "role": user.role})
    return _session_info(user)


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
    
    validate_password_strength(body.new_password)
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    user.password_hash = hash_password(body.new_password)
    await db.commit()
    return {"message": "Password changed successfully"}
