from sqlalchemy import inspect, text
from sqlalchemy.schema import CreateColumn
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings


class Base(DeclarativeBase):
    pass


def _create_engine(database_url: str):
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite+aiosqlite") else {}
    return create_async_engine(database_url, echo=False, pool_pre_ping=True, connect_args=connect_args)


engine = _create_engine(settings.DATABASE_URL)
async_session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db() -> None:
    from app.models import db_models  # noqa: F401 — register ORM models

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_add_missing_columns)


def _add_missing_columns(sync_conn) -> None:
    inspector = inspect(sync_conn)
    existing_tables = set(inspector.get_table_names())
    dialect = sync_conn.dialect

    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            continue

        existing_columns = {column["name"] for column in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in existing_columns:
                continue
            column_sql = str(CreateColumn(column).compile(dialect=dialect)).replace(" NOT NULL", "")
            sync_conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN {column_sql}'))


async def close_db() -> None:
    await engine.dispose()
