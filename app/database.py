from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


class Base(DeclarativeBase):
    pass


_FALLBACK_SQLITE_URL = "sqlite+aiosqlite:///./vulnexus_local.db"


def _create_engine(database_url: str):
    return create_async_engine(database_url, echo=False, pool_pre_ping=True)


engine = _create_engine(settings.DATABASE_URL)
async_session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def _switch_to_fallback_engine() -> None:
    global engine, async_session_maker
    if str(settings.DATABASE_URL).startswith("sqlite+"):
        return

    Path("vulnexus_local.db").touch(exist_ok=True)
    try:
        await engine.dispose()
    except Exception:
        pass
    engine = _create_engine(_FALLBACK_SQLITE_URL)
    async_session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    logger.warning("Falling back to local SQLite database at %s", _FALLBACK_SQLITE_URL)


async def init_db() -> None:
    from app.models import db_models  # noqa: F401 — register ORM models

    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as exc:
        logger.warning("Primary database initialization failed: %s", exc)
        await _switch_to_fallback_engine()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    await engine.dispose()
