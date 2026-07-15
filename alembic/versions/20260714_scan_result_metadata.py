"""Persist scan-level provider metadata such as free-plan intelligence skips.

Revision ID: 20260714_scan_result_metadata
Revises: 20260714_ai_explanation_storage
Create Date: 2026-07-14
"""

from alembic import op
import sqlalchemy as sa


revision = "20260714_scan_result_metadata"
down_revision = "20260714_ai_explanation_storage"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("result_metadata", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "result_metadata")
