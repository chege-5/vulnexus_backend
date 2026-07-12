#!/usr/bin/env python3
"""Apply the Alembic schema to the configured database."""
import asyncio
import os
import subprocess
import sys

BACKEND_DIR = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, BACKEND_DIR)


async def main():
    from app.database import close_db, init_db

    print("Applying Alembic migrations to the configured database...")
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND_DIR,
        check=True,
    )
    await init_db()
    await close_db()
    print("Database schema is current.")


if __name__ == "__main__":
    asyncio.run(main())
