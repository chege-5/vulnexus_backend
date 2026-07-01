from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from app import database


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with database.async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


init_db = database.init_db
close_db = database.close_db
async_session_maker = database.async_session_maker


__all__ = ["get_db", "init_db", "close_db", "async_session_maker"]
