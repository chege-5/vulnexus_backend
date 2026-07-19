"""Persist administrator workspace settings and saved views.

Revision ID: 20260719_admin_workspace
Revises: 20260719_single_admin
Create Date: 2026-07-19
"""

from alembic import op
import sqlalchemy as sa


revision = "20260719_admin_workspace"
down_revision = "20260719_single_admin"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "admin_workspaces",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("settings", sa.JSON(), server_default=sa.text("'{}'"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("owner_id"),
    )
    op.create_index("ix_admin_workspaces_owner_id", "admin_workspaces", ["owner_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_admin_workspaces_owner_id", table_name="admin_workspaces")
    op.drop_table("admin_workspaces")
