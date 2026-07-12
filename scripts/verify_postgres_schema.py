#!/usr/bin/env python3
"""Verify selected PostgreSQL schema constraints used by runtime persistence."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from sqlalchemy import text

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.database import close_db, engine


async def main() -> None:
    async with engine.connect() as conn:
        result = await conn.execute(
            text(
                """
                SELECT character_maximum_length
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = :table_name
                  AND column_name = :column_name
                """
            ),
            {"table_name": "vulnerabilities", "column_name": "rule_id"},
        )
        length = result.scalar_one()
    await close_db()
    print(f"vulnerabilities.rule_id length={length}")


if __name__ == "__main__":
    asyncio.run(main())
