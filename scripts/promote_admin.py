#!/usr/bin/env python3
"""Promote an existing user to admin by email."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


async def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/promote_admin.py user@example.com")
        sys.exit(1)

    email = sys.argv[1].strip().lower()
    from sqlalchemy import select

    from app.database import async_session_maker, close_db
    from app.models.db_models import User

    async with async_session_maker() as db:
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        if not user:
            print(f"No user found with email: {email}")
            await close_db()
            sys.exit(1)
        user.role = "admin"
        await db.commit()

    await close_db()
    print(f"Promoted {email} to admin.")


if __name__ == "__main__":
    asyncio.run(main())
