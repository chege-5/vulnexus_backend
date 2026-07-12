from __future__ import annotations

import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.database import _assert_schema_is_current


ROOT = Path(__file__).resolve().parents[1]
HEAD = "20260707_lifecycle_projects"
PRE_LIFECYCLE = "20260704_utc_timestamps"
TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")


def _alembic(database_url: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["DATABASE_URL"] = database_url
    env["ASYNC_DATABASE_URL"] = database_url
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )


def _reset_database(database_url: str, revision: str = "head") -> None:
    _alembic(database_url, "downgrade", "base")
    _alembic(database_url, "upgrade", revision)


async def _column_names(connection, table_name: str) -> set[str]:
    result = await connection.execute(
        text(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = :table_name
            """
        ),
        {"table_name": table_name},
    )
    return {row.column_name for row in result}


@pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL must point to a disposable PostgreSQL database",
)
@pytest.mark.asyncio
async def test_fresh_postgresql_upgrade_has_current_auth_schema() -> None:
    assert TEST_DATABASE_URL is not None
    _reset_database(TEST_DATABASE_URL)

    engine = create_async_engine(TEST_DATABASE_URL)
    async with engine.connect() as connection:
        columns = await _column_names(connection, "users")
        revision = (await connection.execute(text("SELECT version_num FROM alembic_version"))).scalar_one()
        assert {"password_reset_token_hash", "password_reset_expires_at"} <= columns
        assert revision == HEAD
    await engine.dispose()


@pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL must point to a disposable PostgreSQL database",
)
@pytest.mark.asyncio
async def test_existing_rows_survive_lifecycle_migration() -> None:
    assert TEST_DATABASE_URL is not None
    _reset_database(TEST_DATABASE_URL, PRE_LIFECYCLE)

    user_id = uuid.uuid4()
    engine = create_async_engine(TEST_DATABASE_URL)
    async with engine.begin() as connection:
        await connection.execute(
            text(
                """
                INSERT INTO users (
                    id, email, password_hash, role, name, phone, carrier,
                    fav_programming_languages, company, job_role, security_focus,
                    subscription_tier, subscription_status, scan_limit,
                    is_approved, pending_approval, mpesa_number, payment_method,
                    auth_provider, created_at
                ) VALUES (
                    :id, :email, :password_hash, :role, :name, :phone, :carrier,
                    CAST(:fav_programming_languages AS json), :company, :job_role, :security_focus,
                    :subscription_tier, :subscription_status, :scan_limit,
                    :is_approved, :pending_approval, :mpesa_number, :payment_method,
                    :auth_provider, :created_at
                )
                """
            ),
            {
                "id": user_id,
                "email": "preserved@example.com",
                "password_hash": "hash",
                "role": "developer",
                "name": "Preserved",
                "phone": "",
                "carrier": "",
                "fav_programming_languages": "[]",
                "company": "",
                "job_role": "",
                "security_focus": "",
                "subscription_tier": "free",
                "subscription_status": "active",
                "scan_limit": 10,
                "is_approved": True,
                "pending_approval": False,
                "mpesa_number": "",
                "payment_method": "",
                "auth_provider": "email",
                "created_at": "2026-07-10 10:00:00+00",
            },
        )

    _alembic(TEST_DATABASE_URL, "upgrade", "head")
    async with engine.connect() as connection:
        assert (await connection.execute(
            text("SELECT email FROM users WHERE id = :id"),
            {"id": user_id},
        )).scalar_one() == "preserved@example.com"
        columns = await _column_names(connection, "users")
        assert {"password_reset_token_hash", "password_reset_expires_at"} <= columns
    await engine.dispose()


@pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL must point to a disposable PostgreSQL database",
)
@pytest.mark.asyncio
async def test_startup_check_rejects_pending_migrations() -> None:
    assert TEST_DATABASE_URL is not None
    _reset_database(TEST_DATABASE_URL, PRE_LIFECYCLE)
    engine = create_async_engine(TEST_DATABASE_URL)
    async with engine.connect() as connection:
        with pytest.raises(RuntimeError, match="alembic upgrade head"):
            await connection.run_sync(_assert_schema_is_current)
    await engine.dispose()


def test_postgresql_offline_migration_sql_compiles() -> None:
    result = _alembic(
        "postgresql+asyncpg://migration_user:masked@localhost/vulnexus",
        "upgrade",
        "head",
        "--sql",
    )
    assert "password_reset_token_hash" in result.stdout
    assert "20260707_lifecycle_projects" in result.stdout
