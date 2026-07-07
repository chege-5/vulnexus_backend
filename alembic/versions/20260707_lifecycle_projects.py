"""finding lifecycle and project ownership

Revision ID: 20260707_lifecycle_projects
Revises: 20260704_utc_timestamps
Create Date: 2026-07-07
"""

from alembic import op
import sqlalchemy as sa


revision = "20260707_lifecycle_projects"
down_revision = "20260704_utc_timestamps"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("slug", sa.String(length=255), nullable=False),
        sa.Column("owner_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("slug"),
    )
    op.create_index("ix_organizations_slug", "organizations", ["slug"])
    op.create_index("ix_organizations_owner_id", "organizations", ["owner_id"])

    op.create_table(
        "organization_members",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("organization_id", "user_id", name="uq_org_member"),
    )
    op.create_index("ix_organization_members_organization_id", "organization_members", ["organization_id"])
    op.create_index("ix_organization_members_user_id", "organization_members", ["user_id"])

    op.create_table(
        "projects",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=True),
        sa.Column("owner_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("slug", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_projects_organization_id", "projects", ["organization_id"])
    op.create_index("ix_projects_owner_id", "projects", ["owner_id"])

    op.add_column("users", sa.Column("password_reset_token_hash", sa.String(length=255), nullable=True))
    op.add_column("users", sa.Column("password_reset_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=True))
    op.add_column("scans", sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id"), nullable=True))
    op.add_column("vulnerabilities", sa.Column("assigned_to_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=True))
    op.create_index("ix_scans_organization_id", "scans", ["organization_id"])
    op.create_index("ix_scans_project_id", "scans", ["project_id"])
    op.create_index("ix_vulnerabilities_assigned_to_id", "vulnerabilities", ["assigned_to_id"])

    op.create_table(
        "finding_comments",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("vulnerability_id", sa.Uuid(), sa.ForeignKey("vulnerabilities.id"), nullable=False),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_finding_comments_vulnerability_id", "finding_comments", ["vulnerability_id"])

    op.create_table(
        "finding_history",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("vulnerability_id", sa.Uuid(), sa.ForeignKey("vulnerabilities.id"), nullable=False),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("from_value", sa.String(length=255), nullable=True),
        sa.Column("to_value", sa.String(length=255), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_finding_history_vulnerability_id", "finding_history", ["vulnerability_id"])


def downgrade() -> None:
    op.drop_table("finding_history")
    op.drop_table("finding_comments")
    op.drop_index("ix_vulnerabilities_assigned_to_id", table_name="vulnerabilities")
    op.drop_index("ix_scans_project_id", table_name="scans")
    op.drop_index("ix_scans_organization_id", table_name="scans")
    op.drop_column("vulnerabilities", "assigned_to_id")
    op.drop_column("scans", "project_id")
    op.drop_column("scans", "organization_id")
    op.drop_column("users", "password_reset_expires_at")
    op.drop_column("users", "password_reset_token_hash")
    op.drop_table("projects")
    op.drop_table("organization_members")
    op.drop_table("organizations")
