"""Persist provider-backed AI explanations for vulnerability case files.

Revision ID: 20260714_ai_explanation_storage
Revises: 20260710_rule_id_length
Create Date: 2026-07-14
"""

from alembic import op
import sqlalchemy as sa


revision = "20260714_ai_explanation_storage"
down_revision = "20260710_rule_id_length"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("vulnerabilities", sa.Column("ai_explanation", sa.JSON(), nullable=True))
    op.add_column("vulnerabilities", sa.Column("ai_explanation_updated_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("vulnerabilities", "ai_explanation_updated_at")
    op.drop_column("vulnerabilities", "ai_explanation")
