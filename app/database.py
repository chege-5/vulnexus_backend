from pathlib import Path

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool

from app.config import settings


class Base(DeclarativeBase):
    pass


def _create_engine(database_url: str):
    engine_options = {"echo": False, "pool_pre_ping": True}
    if settings.VULNEXUS_CELERY_WORKER:
        # A solo Celery worker owns short-lived event loops. Do not retain
        # asyncpg connections between task loops.
        engine_options["poolclass"] = NullPool
    return create_async_engine(database_url, **engine_options)


engine = _create_engine(settings.DATABASE_URL)
async_session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


def _assert_schema_is_current(sync_connection) -> None:
    config_path = Path(__file__).resolve().parents[1] / "alembic.ini"
    alembic_config = Config(str(config_path))
    script = ScriptDirectory.from_config(alembic_config)
    expected_heads = set(script.get_heads())
    current_heads = set(MigrationContext.configure(sync_connection).get_current_heads())
    if current_heads != expected_heads:
        current = ", ".join(sorted(current_heads)) or "unversioned"
        expected = ", ".join(sorted(expected_heads)) or "none"
        raise RuntimeError(
            "Database schema is outdated "
            f"(current: {current}; expected: {expected}). Run: alembic upgrade head"
        )


async def check_schema_current() -> None:
    async with engine.connect() as conn:
        await conn.run_sync(_assert_schema_is_current)


async def init_db() -> None:
    """Verify connectivity and refuse to run against an outdated schema."""
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    await check_schema_current()


async def close_db() -> None:
    await engine.dispose()
