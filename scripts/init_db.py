#!/usr/bin/env python3
"""PostgreSQL schema initialization."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


async def main():
    from app.database import init_db, close_db

    print("Initializing PostgreSQL schema...")
    await init_db()
    await close_db()
    print("PostgreSQL schema initialized successfully.")


if __name__ == "__main__":
    asyncio.run(main())
