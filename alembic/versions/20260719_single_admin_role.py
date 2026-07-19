"""Normalize the historical super_admin role to the single admin role.

Revision ID: 20260719_single_admin
Revises: 20260719_resend_email
Create Date: 2026-07-19
"""

from alembic import op


revision = "20260719_single_admin"
down_revision = "20260719_resend_email"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("UPDATE users SET role = 'admin' WHERE role = 'super_admin'")
    op.execute("UPDATE organization_members SET role = 'admin' WHERE role = 'super_admin'")


def downgrade() -> None:
    # The old hierarchy intentionally cannot be reconstructed after normalization.
    pass
