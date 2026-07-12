"""Widen vulnerability rule identifiers.

Revision ID: 20260710_rule_id_length
Revises: 20260707_lifecycle_projects
Create Date: 2026-07-10
"""

from alembic import op
import sqlalchemy as sa


revision = "20260710_rule_id_length"
down_revision = "20260707_lifecycle_projects"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "vulnerabilities",
        "rule_id",
        existing_type=sa.String(length=128),
        type_=sa.String(length=255),
        existing_nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        "vulnerabilities",
        "rule_id",
        existing_type=sa.String(length=255),
        type_=sa.String(length=128),
        existing_nullable=True,
    )
