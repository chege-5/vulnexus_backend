from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from jose import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.auth import hash_password, hash_token
from app.config import settings
from app.deps import get_db
from app.main import app
from app.models.db_models import OAuthAccount, User
from app.routes import auth_routes
from app.services.oauth import oauth_login_or_register


ROOT = Path(__file__).resolve().parents[1]
TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")


pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL must point to a disposable PostgreSQL database",
)


@pytest_asyncio.fixture
async def auth_context(monkeypatch: pytest.MonkeyPatch):
    assert TEST_DATABASE_URL is not None
    database_url = TEST_DATABASE_URL
    env = os.environ.copy()
    env["DATABASE_URL"] = database_url
    env["ASYNC_DATABASE_URL"] = database_url
    subprocess.run(
        [sys.executable, "-m", "alembic", "downgrade", "base"],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    engine = create_async_engine(database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def override_get_db():
        async with sessions() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    delivered_codes: dict[str, list[str]] = {"reset": [], "verification": []}

    async def fake_send_password_reset_email(recipient: str, code: str) -> None:
        assert recipient == "user@example.com"
        delivered_codes["reset"].append(code)

    async def fake_send_email_verification(recipient: str, code: str) -> None:
        assert recipient == "user@example.com"
        delivered_codes["verification"].append(code)

    monkeypatch.setattr(auth_routes, "send_password_reset_email", fake_send_password_reset_email)
    monkeypatch.setattr(auth_routes, "send_email_verification", fake_send_email_verification)
    app.dependency_overrides[get_db] = override_get_db
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client, sessions, delivered_codes

    app.dependency_overrides.clear()
    await engine.dispose()


@pytest.mark.asyncio
async def test_complete_email_authentication_and_reset_flow(auth_context) -> None:
    client, sessions, delivered_codes = auth_context
    registration = {
        "email": "User@Example.com",
        "password": "OldPassword!42",
        "name": "Database User",
    }

    assert (await client.post("/api/v1/auth/login", json={"email": "bad"})).status_code == 422
    registered = await client.post("/api/v1/auth/register", json=registration)
    assert registered.status_code == 201
    assert registered.json()["user"]["email"] == "user@example.com"
    assert (await client.post("/api/v1/auth/register", json=registration)).status_code == 409

    verification = await client.post(
        "/api/v1/auth/verify-email",
        json={"email": "user@example.com", "code": delivered_codes["verification"][-1]},
    )
    assert verification.status_code == 200
    assert verification.json()["user"]["email_verified"] is True

    bad_password = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com", "password": "WrongPassword!42"},
    )
    unknown_email = await client.post(
        "/api/v1/auth/login",
        json={"email": "unknown@example.com", "password": "WrongPassword!42"},
    )
    assert bad_password.status_code == unknown_email.status_code == 401
    assert bad_password.json() == unknown_email.json()

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com", "password": "OldPassword!42"},
    )
    assert login.status_code == 200
    claims = jwt.decode(login.json()["access_token"], settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert claims["role"] == "developer"
    assert (await client.post("/api/v1/auth/refresh", json={})).status_code == 200

    unknown_reset = await client.post(
        "/api/v1/auth/forgot-password", json={"email": "unknown@example.com"}
    )
    known_reset = await client.post(
        "/api/v1/auth/forgot-password", json={"email": "USER@example.com"}
    )
    assert unknown_reset.status_code == known_reset.status_code == 200
    assert unknown_reset.json() == known_reset.json()
    code = delivered_codes["reset"][-1]
    async with sessions() as session:
        user = (await session.execute(select(User).where(User.email == "user@example.com"))).scalar_one()
        assert user.password_reset_token_hash == hash_token(code)
        assert user.password_reset_token_hash != code
        user.password_reset_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await session.commit()

    expired = await client.post(
        "/api/v1/auth/reset-password",
        json={"email": "user@example.com", "code": code, "new_password": "NewPassword!42"},
    )
    assert expired.status_code == 400

    await client.post("/api/v1/auth/forgot-password", json={"email": "user@example.com"})
    code = delivered_codes["reset"][-1]
    verified_code = await client.post(
        "/api/v1/auth/validate-reset-code",
        json={"email": "user@example.com", "code": code},
    )
    assert verified_code.status_code == 200
    reset = await client.post(
        "/api/v1/auth/reset-password",
        json={"email": "user@example.com", "code": code, "new_password": "NewPassword!42"},
    )
    assert reset.status_code == 200
    assert reset.json()["access_token"]
    assert (
        await client.post(
            "/api/v1/auth/reset-password",
            json={"email": "user@example.com", "code": code, "new_password": "AnotherPassword!42"},
        )
    ).status_code == 400
    assert (
        await client.post(
            "/api/v1/auth/login",
            json={"email": "user@example.com", "password": "OldPassword!42"},
        )
    ).status_code == 401
    new_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com", "password": "NewPassword!42"},
    )
    assert new_login.status_code == 200

    logout = await client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {new_login.json()['access_token']}"},
    )
    assert logout.status_code == 200
    assert (await client.post("/api/v1/auth/refresh", json={})).status_code == 401


@pytest.mark.asyncio
async def test_oauth_user_and_super_admin_roles_are_schema_compatible(auth_context) -> None:
    client, sessions, _ = auth_context
    async with sessions() as session:
        oauth_user, oauth_token = await oauth_login_or_register(
            db=session,
            provider="google",
            provider_user_id="google-123",
            email="oauth@example.com",
            name="OAuth User",
            avatar_url=None,
        )
        # OAuth-only accounts receive an inaccessible random password, so email
        # login cannot bypass the provider flow even though the column is nullable.
        assert oauth_user.auth_provider == "google"
        assert oauth_user.password_hash is not None
        assert (await session.execute(select(OAuthAccount))).scalar_one().provider == "google"
        oauth_claims = jwt.decode(oauth_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert oauth_claims["role"] == "developer"

        admin = User(
            email="admin@example.com",
            password_hash=hash_password("AdminPassword!42"),
            role="super_admin",
            name="Admin",
        )
        session.add(admin)
        await session.commit()

    oauth_email_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "oauth@example.com", "password": "AnyPassword!42"},
    )
    assert oauth_email_login.status_code == 401
    admin_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "AdminPassword!42"},
    )
    assert admin_login.status_code == 200
    assert admin_login.json()["user"]["role"] == "super_admin"
    admin_claims = jwt.decode(admin_login.json()["access_token"], settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert admin_claims["role"] == "super_admin"
