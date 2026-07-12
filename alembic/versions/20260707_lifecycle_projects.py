"""Add finding lifecycle, projects, and password-reset support.

Revision ID: 20260707_lifecycle_projects
Revises: 20260704_utc_timestamps
Create Date: 2026-07-07

The existence checks intentionally support databases previously bootstrapped by
``Base.metadata.create_all()``. They inspect known objects and never suppress an
unexpected database exception.
"""

from alembic import context, op
import sqlalchemy as sa


revision = "20260707_lifecycle_projects"
down_revision = "20260704_utc_timestamps"
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def _has_table(name: str) -> bool:
    if context.is_offline_mode():
        return False
    return name in _inspector().get_table_names()


def _has_column(table: str, column: str) -> bool:
    if context.is_offline_mode():
        return False
    return column in {item["name"] for item in _inspector().get_columns(table)}


def _has_index(table: str, name: str) -> bool:
    if context.is_offline_mode():
        return False
    return name in {item["name"] for item in _inspector().get_indexes(table)}


def _has_fk(table: str, constrained_column: str) -> bool:
    if context.is_offline_mode():
        return False
    return constrained_column in {
        column
        for fk in _inspector().get_foreign_keys(table)
        for column in fk["constrained_columns"]
    }


def _index(table: str, name: str, columns: list[str]) -> None:
    if not _has_index(table, name):
        op.create_index(name, table, columns)


def _add_reference_column(
    table: str,
    column: str,
    referred_table: str,
    index_name: str,
) -> None:
    needs_column = not _has_column(table, column)
    needs_fk = not _has_fk(table, column)
    if needs_column or needs_fk:
        with op.batch_alter_table(table) as batch_op:
            if needs_column:
                batch_op.add_column(sa.Column(column, sa.Uuid(), nullable=True))
            if needs_fk:
                batch_op.create_foreign_key(
                    f"fk_{table}_{column}_{referred_table}",
                    referred_table,
                    [column],
                    ["id"],
                )
    _index(table, index_name, [column])


def upgrade() -> None:
    if not _has_table("organizations"):
        op.create_table(
            "organizations",
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("slug", sa.String(255), nullable=False),
            sa.Column("owner_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("slug"),
        )
    _index("organizations", "ix_organizations_slug", ["slug"])
    _index("organizations", "ix_organizations_owner_id", ["owner_id"])

    if not _has_table("organization_members"):
        op.create_table(
            "organization_members",
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
            sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("role", sa.String(32), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("organization_id", "user_id", name="uq_org_member"),
        )
    _index("organization_members", "ix_organization_members_organization_id", ["organization_id"])
    _index("organization_members", "ix_organization_members_user_id", ["user_id"])

    if not _has_table("projects"):
        op.create_table(
            "projects",
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=True),
            sa.Column("owner_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("slug", sa.String(255), nullable=False),
            sa.Column("description", sa.Text(), nullable=False, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
    _index("projects", "ix_projects_organization_id", ["organization_id"])
    _index("projects", "ix_projects_owner_id", ["owner_id"])
    _index("projects", "ix_projects_slug", ["slug"])

    missing_reset_columns = []
    if not _has_column("users", "password_reset_token_hash"):
        missing_reset_columns.append(sa.Column("password_reset_token_hash", sa.String(255), nullable=True))
    if not _has_column("users", "password_reset_expires_at"):
        missing_reset_columns.append(sa.Column("password_reset_expires_at", sa.DateTime(timezone=True), nullable=True))
    if missing_reset_columns:
        with op.batch_alter_table("users") as batch_op:
            for column in missing_reset_columns:
                batch_op.add_column(column)

    _add_reference_column("scans", "organization_id", "organizations", "ix_scans_organization_id")
    _add_reference_column("scans", "project_id", "projects", "ix_scans_project_id")
    _add_reference_column("vulnerabilities", "assigned_to_id", "users", "ix_vulnerabilities_assigned_to_id")

    if not _has_table("finding_comments"):
        op.create_table(
            "finding_comments",
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("vulnerability_id", sa.Uuid(), sa.ForeignKey("vulnerabilities.id"), nullable=False),
            sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
    for column in ("vulnerability_id", "user_id", "created_at"):
        _index("finding_comments", f"ix_finding_comments_{column}", [column])

    if not _has_table("finding_history"):
        op.create_table(
            "finding_history",
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("vulnerability_id", sa.Uuid(), sa.ForeignKey("vulnerabilities.id"), nullable=False),
            sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("action", sa.String(64), nullable=False),
            sa.Column("from_value", sa.String(255), nullable=True),
            sa.Column("to_value", sa.String(255), nullable=True),
            sa.Column("details", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
    for column in ("vulnerability_id", "user_id", "created_at"):
        _index("finding_history", f"ix_finding_history_{column}", [column])


def downgrade() -> None:
    op.drop_table("finding_history")
    op.drop_table("finding_comments")
    with op.batch_alter_table("vulnerabilities") as batch_op:
        batch_op.drop_column("assigned_to_id")
    with op.batch_alter_table("scans") as batch_op:
        batch_op.drop_column("project_id")
        batch_op.drop_column("organization_id")
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("password_reset_expires_at")
        batch_op.drop_column("password_reset_token_hash")
    op.drop_table("projects")
    op.drop_table("organization_members")
    op.drop_table("organizations")
