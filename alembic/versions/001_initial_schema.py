"""initial schema

Revision ID: 001
Revises:
Create Date: 2026-03-07
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), unique=True, nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )

    scantype_enum = sa.Enum("file", "url", name="scantype")
    scanstatus_enum = sa.Enum("queued", "in_progress", "completed", "failed", name="scanstatus")

    op.create_table(
        "scans",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("type", scantype_enum, nullable=False),
        sa.Column("target", sa.Text, nullable=False),
        sa.Column("status", scanstatus_enum, server_default="queued"),
        sa.Column("progress", sa.Integer, server_default="0"),
        sa.Column("queued_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("finished_at", sa.DateTime, nullable=True),
        sa.Column("overall_score", sa.Float, nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
    )

    op.create_table(
        "scan_files",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("filename", sa.String(512), nullable=False),
        sa.Column("path", sa.Text, nullable=False),
        sa.Column("features_json", sa.JSON, nullable=True),
    )

    op.create_table(
        "cve_entries",
        sa.Column("cve_id", sa.String(50), primary_key=True),
        sa.Column("summary", sa.Text, nullable=True),
        sa.Column("cvss_score", sa.Float, nullable=True),
        sa.Column("published_date", sa.DateTime, nullable=True),
        sa.Column("last_modified", sa.DateTime, nullable=True),
    )

    severity_enum = sa.Enum("Low", "Medium", "High", "Critical", name="severity")

    op.create_table(
        "vulnerabilities",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("rule_id", sa.String(100), nullable=True),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("severity", severity_enum, nullable=False),
        sa.Column("ml_score", sa.Float, nullable=True),
        sa.Column("cve_id", sa.String(50), sa.ForeignKey("cve_entries.cve_id"), nullable=True),
        sa.Column("file_path", sa.Text, nullable=True),
        sa.Column("line_number", sa.Integer, nullable=True),
        sa.Column("remediation", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )

    op.create_table(
        "ml_features",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("features_json", sa.JSON, nullable=False),
        sa.Column("label", sa.String(50), nullable=True),
    )

    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_scans_user_id", "scans", ["user_id"])
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_index("ix_vulnerabilities_scan_id", "vulnerabilities", ["scan_id"])


def downgrade() -> None:
    op.drop_table("ml_features")
    op.drop_table("vulnerabilities")
    op.drop_table("cve_entries")
    op.drop_table("scan_files")
    op.drop_table("scans")
    op.drop_table("users")
    op.execute("DROP TYPE IF EXISTS scantype")
    op.execute("DROP TYPE IF EXISTS scanstatus")
    op.execute("DROP TYPE IF EXISTS severity")
