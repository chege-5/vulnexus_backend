"""Track report attachment delivery per scan.

Revision ID: 20260720_report_email
Revises: 20260719_admin_workspace
Create Date: 2026-07-20
"""

from alembic import op
import sqlalchemy as sa


revision = "20260720_report_email"
down_revision = "20260719_admin_workspace"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("report_email_sent_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "report_email_sent_at")
