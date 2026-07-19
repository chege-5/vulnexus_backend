"""Add transactional email delivery state and preferences.

Revision ID: 20260719_resend_email
Revises: 20260717_ai_review_status
Create Date: 2026-07-19
"""

from alembic import op
import sqlalchemy as sa


revision = "20260719_resend_email"
down_revision = "20260717_ai_review_status"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("email_verification_sent_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("welcome_email_sent_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("email_preferences", sa.JSON(), nullable=False, server_default=sa.text("'{}'")))


def downgrade() -> None:
    op.drop_column("users", "email_preferences")
    op.drop_column("users", "welcome_email_sent_at")
    op.drop_column("users", "email_verification_sent_at")
