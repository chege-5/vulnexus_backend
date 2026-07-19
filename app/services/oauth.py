"""OAuth and GitHub account integration helpers."""
from __future__ import annotations

import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import create_access_token, hash_password
from app.core.http_client import create_async_client, request_with_retry
from app.config import settings
from app.models.db_models import GitHubConnection, OAuthAccount, User
from app.utils.crypto import decrypt_token, encrypt_token
from app.utils.logger import get_logger


logger = get_logger(__name__)


def build_google_auth_url(state: str, redirect_uri: Optional[str] = None) -> str:
    if not settings.GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=501, detail="Google authentication not configured")

    selected_redirect_uri = redirect_uri or settings.GOOGLE_REDIRECT_URI
    logger.info("Google OAuth auth URL build: redirect_uri=%s", selected_redirect_uri)
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": selected_redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "true",
        "state": state,
    }
    return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"


async def verify_google_token(id_token: str) -> dict:
    logger.info("Google OAuth token verification started")
    async with create_async_client(timeout=15) as client:
        response = await request_with_retry(client, "GET", f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}")
        if response is None or response.status_code != 200:
            logger.warning("Google OAuth token verification failed: tokeninfo returned no valid response")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Google token",
            )

        data = response.json()
        if data.get("iss") not in {"https://accounts.google.com", "accounts.google.com"}:
            logger.warning("Google OAuth token verification failed: issuer mismatch")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Google token issuer",
            )
        if data.get("aud") != settings.GOOGLE_CLIENT_ID:
            logger.warning("Google OAuth token verification failed: audience mismatch")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token audience mismatch",
            )

        try:
            expires_at = int(data["exp"])
        except (KeyError, TypeError, ValueError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Google token expiration is invalid",
            )
        if expires_at <= int(time.time()):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Google token has expired",
            )

        if data.get("email_verified") not in (True, "true", "True", "1"):
            logger.warning("Google OAuth token verification failed: email is not verified")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Google account email is not verified",
            )

        logger.info("Google OAuth token verification succeeded: email=%s", data.get("email", ""))
        return {
            "provider_user_id": data["sub"],
            "email": data.get("email", ""),
            "name": data.get("name", ""),
            "avatar_url": data.get("picture", ""),
            "email_verified": True,
        }


async def exchange_google_code(code: str, redirect_uri: Optional[str] = None) -> dict:
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        raise HTTPException(status_code=501, detail="Google OAuth is not configured")

    selected_redirect_uri = redirect_uri or settings.GOOGLE_REDIRECT_URI
    logger.info("Google OAuth code exchange started: redirect_uri=%s", selected_redirect_uri)
    async with create_async_client(timeout=20) as client:
        token_response = await request_with_retry(
            client,
            "POST",
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": selected_redirect_uri,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if token_response is None or token_response.status_code != 200:
            detail = "Failed to exchange Google code"
            status_code = token_response.status_code if token_response is not None else "no_response"
            if token_response is not None:
                try:
                    error_payload = token_response.json()
                    error_description = error_payload.get("error_description") or error_payload.get("error")
                    if error_description:
                        detail = f"Google OAuth exchange failed: {error_description}"
                except Exception:
                    pass
            logger.warning("Google OAuth code exchange failed: status=%s", status_code)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=detail,
            )

        token_data = token_response.json()
        id_token = token_data.get("id_token")
        if not id_token:
            logger.warning("Google OAuth code exchange failed: ID token missing")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Google token exchange did not return an ID token",
            )

        logger.info("Google OAuth code exchange succeeded; verifying profile")
        identity = await verify_google_token(id_token)
        identity["access_token"] = token_data.get("access_token")
        identity["refresh_token"] = token_data.get("refresh_token")
        return identity


def build_github_auth_url(state: str, redirect_uri: Optional[str] = None) -> str:
    if not settings.GITHUB_CLIENT_ID:
        raise HTTPException(status_code=501, detail="GitHub authentication not configured")

    params = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "redirect_uri": redirect_uri or settings.GITHUB_REDIRECT_URI,
        "response_type": "code",
        "scope": settings.GITHUB_OAUTH_SCOPE,
        "state": state,
        "allow_signup": "true",
    }
    return f"https://github.com/login/oauth/authorize?{urlencode(params)}"


async def exchange_github_code(code: str, redirect_uri: Optional[str] = None) -> dict:
    if not settings.GITHUB_CLIENT_ID or not settings.GITHUB_CLIENT_SECRET:
        raise HTTPException(status_code=501, detail="GitHub OAuth is not configured")

    async with create_async_client(timeout=20) as client:
        token_response = await request_with_retry(
            client,
            "POST",
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": redirect_uri or settings.GITHUB_REDIRECT_URI,
            },
            headers={"Accept": "application/json"},
        )
        if token_response is None or token_response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Failed to exchange GitHub code",
            )

        token_data = token_response.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No access token returned from GitHub",
            )

        user_response = await request_with_retry(client, "GET", "https://api.github.com/user", headers=_github_headers(access_token))
        if user_response is None or user_response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Failed to get GitHub user info",
            )
        user_data = user_response.json()

        email = await _github_primary_email(client, access_token, user_data.get("login", ""))
        metadata = await fetch_github_metadata(access_token, user_data.get("login", ""))

        return {
            "provider_user_id": str(user_data["id"]),
            "email": email,
            "name": user_data.get("name") or user_data.get("login", ""),
            "avatar_url": user_data.get("avatar_url", ""),
            "access_token": access_token,
            "github_username": user_data.get("login", ""),
            "metadata": metadata,
        }


async def fetch_github_metadata(access_token: str, github_username: str) -> dict:
    async with create_async_client(timeout=20) as client:
        org_response = await request_with_retry(client, "GET", "https://api.github.com/user/orgs", headers=_github_headers(access_token))
        repos_response = await request_with_retry(
            client,
            "GET",
            "https://api.github.com/user/repos",
            params={"per_page": 100, "sort": "updated"},
            headers=_github_headers(access_token),
        )

    organizations: list[dict] = []
    if org_response is not None and org_response.status_code == 200:
        for org in org_response.json():
            organizations.append({
                "login": org.get("login"),
                "id": org.get("id"),
                "avatar_url": org.get("avatar_url"),
                "description": org.get("description"),
            })

    repositories: list[dict] = []
    permissions: dict[str, bool] = {}
    if repos_response is not None and repos_response.status_code == 200:
        for repo in repos_response.json():
            repo_permissions = repo.get("permissions") or {}
            permissions = _merge_permissions(permissions, repo_permissions)
            repositories.append({
                "owner": repo.get("owner", {}).get("login"),
                "name": repo.get("name"),
                "full_name": repo.get("full_name"),
                "private": repo.get("private", False),
                "default_branch": repo.get("default_branch"),
                "html_url": repo.get("html_url"),
                "description": repo.get("description"),
                "permissions": repo_permissions,
                "branches": [repo.get("default_branch")] if repo.get("default_branch") else [],
            })

    return {
        "github_username": github_username,
        "organizations": organizations,
        "repositories": repositories,
        "permissions": permissions,
    }


async def list_github_branches(access_token: str, owner: str, repo: str) -> list[str]:
    async with create_async_client(timeout=20) as client:
        response = await request_with_retry(
            client,
            "GET",
            f"https://api.github.com/repos/{owner}/{repo}/branches",
            params={"per_page": 100},
            headers=_github_headers(access_token),
        )
        if response is None or response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Unable to fetch repository branches",
            )
        return [item.get("name") for item in response.json() if item.get("name")]


async def oauth_login_or_register(
    db: AsyncSession,
    provider: str,
    provider_user_id: str,
    email: str,
    name: str,
    avatar_url: str = "",
    access_token: Optional[str] = None,
    refresh_token: Optional[str] = None,
    github_username: Optional[str] = None,
    metadata: Optional[dict] = None,
    current_user: Optional[User] = None,
    provider_email_verified: bool = False,
) -> tuple[User, str]:
    result = await db.execute(
        select(OAuthAccount).where(
            OAuthAccount.provider == provider,
            OAuthAccount.provider_user_id == provider_user_id,
        )
    )
    oauth_account = result.scalar_one_or_none()

    if oauth_account:
        logger.info("OAuth account found: provider=%s provider_user_id=%s", provider, provider_user_id)
        user_result = await db.execute(select(User).where(User.id == oauth_account.user_id))
        user = user_result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=500, detail="User not found for OAuth account")
        if current_user and user.id != current_user.id:
            logger.warning("OAuth link rejected: provider=%s provider_user_id=%s already linked", provider, provider_user_id)
            raise HTTPException(status_code=409, detail="This provider account is already linked to another user")
        if not user.is_approved or user.pending_approval:
            raise HTTPException(status_code=403, detail="Account is pending approval")
        if provider_email_verified and user.email == email.lower():
            user.email_verified = True

        oauth_account.access_token = access_token or oauth_account.access_token
        oauth_account.refresh_token = refresh_token or oauth_account.refresh_token
        oauth_account.expires_at = datetime.now(timezone.utc) + timedelta(days=365)
        user.last_login = datetime.now(timezone.utc)
        user.avatar_url = avatar_url or user.avatar_url
        if provider == "github" and access_token and github_username:
            await _upsert_github_connection(db, user.id, github_user_id=provider_user_id, github_username=github_username, access_token=access_token, metadata=metadata)

        await db.commit()
        logger.info("OAuth existing provider login completed: provider=%s user_id=%s", provider, user.id)
        return user, create_access_token({"sub": str(user.id), "role": user.role})

    target_user = current_user
    if target_user is None:
        email_result = await db.execute(select(User).where(User.email == email.lower()))
        target_user = email_result.scalar_one_or_none()

    if target_user:
        logger.info("OAuth email match found: provider=%s user_id=%s email=%s", provider, target_user.id, target_user.email)
        if not target_user.is_approved or target_user.pending_approval:
            raise HTTPException(status_code=403, detail="Account is pending approval")
        existing_link_result = await db.execute(
            select(OAuthAccount).where(
                OAuthAccount.user_id == target_user.id,
                OAuthAccount.provider == provider,
            )
        )
        existing_link = existing_link_result.scalar_one_or_none()
        if existing_link is None:
            logger.info("OAuth account link created: provider=%s user_id=%s", provider, target_user.id)
            db.add(OAuthAccount(
                user_id=target_user.id,
                provider=provider,
                provider_user_id=provider_user_id,
                access_token=access_token,
                refresh_token=refresh_token,
                expires_at=datetime.now(timezone.utc) + timedelta(days=365),
            ))
        else:
            logger.info("OAuth account link updated: provider=%s user_id=%s", provider, target_user.id)
            existing_link.provider_user_id = provider_user_id
            existing_link.access_token = access_token or existing_link.access_token
            existing_link.refresh_token = refresh_token or existing_link.refresh_token
            existing_link.expires_at = datetime.now(timezone.utc) + timedelta(days=365)

        target_user.avatar_url = avatar_url or target_user.avatar_url
        if provider_email_verified and target_user.email == email.lower():
            target_user.email_verified = True
        target_user.last_login = datetime.now(timezone.utc)
        if provider == "github" and access_token and github_username:
            await _upsert_github_connection(db, target_user.id, github_user_id=provider_user_id, github_username=github_username, access_token=access_token, metadata=metadata)

        await db.commit()
        logger.info("OAuth email-linked login completed: provider=%s user_id=%s", provider, target_user.id)
        return target_user, create_access_token({"sub": str(target_user.id), "role": target_user.role})

    logger.info("OAuth user creation started: provider=%s email=%s", provider, email.lower())
    user = User(
        email=email.lower(),
        name=name,
        avatar_url=avatar_url,
        auth_provider=provider,
        password_hash=hash_password(str(uuid.uuid4()) + secrets.token_urlsafe(16)),
        role="developer",
        is_approved=True,
        scan_limit=10,
        email_verified=provider_email_verified,
        last_login=datetime.now(timezone.utc),
    )
    db.add(user)
    await db.flush()

    db.add(OAuthAccount(
        user_id=user.id,
        provider=provider,
        provider_user_id=provider_user_id,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=datetime.now(timezone.utc) + timedelta(days=365),
    ))

    if provider == "github" and access_token and github_username:
        await _upsert_github_connection(db, user.id, github_user_id=provider_user_id, github_username=github_username, access_token=access_token, metadata=metadata)

    await db.commit()
    await db.refresh(user)
    logger.info("OAuth user creation completed: provider=%s user_id=%s", provider, user.id)
    return user, create_access_token({"sub": str(user.id), "role": user.role})


async def _upsert_github_connection(
    db: AsyncSession,
    user_id: uuid.UUID,
    github_user_id: str,
    github_username: str,
    access_token: str,
    metadata: Optional[dict] = None,
) -> GitHubConnection:
    result = await db.execute(select(GitHubConnection).where(GitHubConnection.user_id == user_id))
    connection = result.scalar_one_or_none()
    encrypted_token = await encrypt_token(access_token)
    organizations = metadata.get("organizations") if metadata else None
    repositories = metadata.get("repositories") if metadata else None

    if connection:
        connection.github_user_id = github_user_id
        connection.github_username = github_username
        connection.access_token = encrypted_token
        connection.token_encrypted = True
        connection.last_synced_at = datetime.now(timezone.utc)
        connection.is_connected = True
        if organizations is not None:
            connection.organizations = organizations
        if repositories is not None:
            connection.repositories = repositories
    else:
        connection = GitHubConnection(
            user_id=user_id,
            github_user_id=github_user_id,
            github_username=github_username,
            access_token=encrypted_token,
            token_encrypted=True,
            connected_at=datetime.now(timezone.utc),
            last_synced_at=datetime.now(timezone.utc),
            is_connected=True,
            organizations=organizations,
            repositories=repositories,
        )
        db.add(connection)

    return connection


async def get_github_connection_payload(db: AsyncSession, user_id: uuid.UUID) -> dict:
    result = await db.execute(select(GitHubConnection).where(GitHubConnection.user_id == user_id))
    connection = result.scalar_one_or_none()
    if not connection:
        return {
            "connected": False,
            "github_username": None,
            "last_synced_at": None,
            "organizations": [],
            "repositories": [],
            "branches": [],
            "permissions": {},
        }

    repositories = connection.repositories or []
    branches = []
    permissions = {}
    for repo in repositories:
        repo_branches = repo.get("branches") or []
        branches.extend([branch for branch in repo_branches if branch])
        permissions = _merge_permissions(permissions, repo.get("permissions") or {})

    return {
        "connected": connection.is_connected,
        "github_username": connection.github_username,
        "github_user_id": connection.github_user_id,
        "connected_at": connection.connected_at,
        "last_synced_at": connection.last_synced_at,
        "organizations": connection.organizations or [],
        "repositories": repositories,
        "branches": sorted(set(branches)),
        "permissions": permissions,
    }


async def sync_github_connection_metadata(db: AsyncSession, user_id: uuid.UUID) -> dict:
    result = await db.execute(select(GitHubConnection).where(GitHubConnection.user_id == user_id))
    connection = result.scalar_one_or_none()
    if not connection:
        raise HTTPException(status_code=404, detail="GitHub account is not connected")

    access_token = await _decrypt_access_token(connection.access_token)
    metadata = await fetch_github_metadata(access_token, connection.github_username)
    connection.organizations = metadata["organizations"]
    connection.repositories = metadata["repositories"]
    connection.last_synced_at = datetime.now(timezone.utc)
    connection.is_connected = True
    await db.commit()

    return await get_github_connection_payload(db, user_id)


async def disconnect_github_connection(db: AsyncSession, user_id: uuid.UUID) -> None:
    result = await db.execute(select(GitHubConnection).where(GitHubConnection.user_id == user_id))
    connection = result.scalar_one_or_none()
    if not connection:
        raise HTTPException(status_code=404, detail="GitHub account is not connected")
    connection.is_connected = False
    connection.last_synced_at = datetime.now(timezone.utc)
    await db.commit()


async def _github_primary_email(client: httpx.AsyncClient, access_token: str, login: str) -> str:
    response = await client.get(
        "https://api.github.com/user/emails",
        headers=_github_headers(access_token),
    )
    if response.status_code == 200:
        emails = response.json()
        primary_email = next((item for item in emails if item.get("primary")), None)
        if primary_email and primary_email.get("email"):
            return primary_email["email"]
        verified_email = next((item for item in emails if item.get("verified") and item.get("email")), None)
        if verified_email and verified_email.get("email"):
            return verified_email["email"]
    return f"{login}@github.local"


async def _decrypt_access_token(encrypted_token: str) -> str:
    try:
        return await decrypt_token(encrypted_token)
    except Exception:
        return encrypted_token


def _github_headers(access_token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _merge_permissions(existing: dict[str, bool], new: dict[str, bool]) -> dict[str, bool]:
    merged = dict(existing)
    for key, value in new.items():
        merged[key] = bool(merged.get(key, False) or value)
    return merged
