#!/usr/bin/env python3
"""Promote an existing user to an RBAC role by email."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

VALID_ADMIN_ROLES = {"admin", "super_admin"}


async def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/promote_admin.py user@example.com [admin|super_admin]")
        sys.exit(1)

    email = sys.argv[1].strip()
    role = sys.argv[2].strip().lower() if len(sys.argv) > 2 else "admin"
    if role not in VALID_ADMIN_ROLES:
        print(f"Invalid role: {role}. Use one of: {', '.join(sorted(VALID_ADMIN_ROLES))}")
        sys.exit(1)

    from sqlalchemy import func, select

    from app.database import async_session_maker, close_db
    from app.models.db_models import OrganizationMember, User

    async with async_session_maker() as db:
        result = await db.execute(select(User).where(func.lower(User.email) == email.lower()))
        user = result.scalar_one_or_none()
        if not user:
            print(f"No user found with email: {email}")
            await close_db()
            sys.exit(1)

        previous_role = user.role
        user.role = role
        user.is_approved = True
        user.pending_approval = False

        memberships = await db.execute(
            select(OrganizationMember).where(OrganizationMember.user_id == user.id)
        )
        for membership in memberships.scalars():
            membership.role = role

        await db.commit()

    await close_db()
    print(f"Promoted {user.email} from {previous_role} to {role}.")


if __name__ == "__main__":
    asyncio.run(main())
