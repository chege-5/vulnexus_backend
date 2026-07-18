"""Store asynchronous AI-review lifecycle separately from scan completion.

Revision ID: 20260717_ai_review_status
Revises: 20260715_auth_verification_mfa
Create Date: 2026-07-17
"""

from alembic import op
import sqlalchemy as sa


revision = "20260717_ai_review_status"
down_revision = "20260715_auth_verification_mfa"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("ai_review_status", sa.String(length=32), nullable=False, server_default="pending"),
    )
    op.add_column("scans", sa.Column("ai_review_error", sa.Text(), nullable=True))
    op.create_index("ix_scans_ai_review_status", "scans", ["ai_review_status"])


def downgrade() -> None:
    op.drop_index("ix_scans_ai_review_status", table_name="scans")
    op.drop_column("scans", "ai_review_error")
    op.drop_column("scans", "ai_review_status")
