"""Establish the pre-lifecycle VulNexus schema.

Revision ID: 20260701_initial_schema
Revises: None
Create Date: 2026-07-01
"""

from alembic import op
import sqlalchemy as sa


revision = "20260701_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=True),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("phone", sa.String(64), nullable=False),
        sa.Column("carrier", sa.String(64), nullable=False),
        sa.Column("fav_programming_languages", sa.JSON(), nullable=False),
        sa.Column("company", sa.String(255), nullable=False),
        sa.Column("job_role", sa.String(255), nullable=False),
        sa.Column("security_focus", sa.String(255), nullable=False),
        sa.Column("subscription_tier", sa.String(64), nullable=False),
        sa.Column("subscription_status", sa.String(64), nullable=False),
        sa.Column("subscription_expires_at", sa.DateTime(), nullable=True),
        sa.Column("trial_ends_at", sa.DateTime(), nullable=True),
        sa.Column("scan_limit", sa.Integer(), nullable=False),
        sa.Column("is_approved", sa.Boolean(), nullable=False),
        sa.Column("pending_approval", sa.Boolean(), nullable=False),
        sa.Column("mpesa_number", sa.String(64), nullable=False),
        sa.Column("payment_method", sa.String(64), nullable=False),
        sa.Column("avatar_url", sa.String(512), nullable=True),
        sa.Column("auth_provider", sa.String(32), nullable=False),
        sa.Column("refresh_token", sa.Text(), nullable=True),
        sa.Column("last_login", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
    )
    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_users_role", "users", ["role"])

    op.create_table(
        "oauth_accounts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("provider_user_id", sa.String(255), nullable=False),
        sa.Column("access_token", sa.Text(), nullable=True),
        sa.Column("refresh_token", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("provider", "provider_user_id", name="uq_oauth_provider_user"),
    )
    op.create_index("ix_oauth_accounts_user_id", "oauth_accounts", ["user_id"])

    op.create_table(
        "github_connections",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("github_user_id", sa.String(255), nullable=False),
        sa.Column("github_username", sa.String(255), nullable=False),
        sa.Column("access_token", sa.Text(), nullable=False),
        sa.Column("token_encrypted", sa.Boolean(), nullable=False),
        sa.Column("connected_at", sa.DateTime(), nullable=False),
        sa.Column("last_synced_at", sa.DateTime(), nullable=True),
        sa.Column("is_connected", sa.Boolean(), nullable=False),
        sa.Column("organizations", sa.JSON(), nullable=True),
        sa.Column("repositories", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_github_connections_user_id", "github_connections", ["user_id"])

    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("target", sa.String(1024), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("queued_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("overall_score", sa.Float(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("github_org", sa.String(255), nullable=True),
        sa.Column("github_repo", sa.String(255), nullable=True),
        sa.Column("github_branch", sa.String(255), nullable=True),
        sa.Column("github_folder", sa.String(512), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scans_user_id", "scans", ["user_id"])
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_index("ix_scans_queued_at", "scans", ["queued_at"])

    op.create_table(
        "scan_files",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("filename", sa.String(512), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("features_json", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scan_files_scan_id", "scan_files", ["scan_id"])

    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("rule_id", sa.String(128), nullable=True),
        sa.Column("ml_score", sa.Float(), nullable=True),
        sa.Column("cve_id", sa.String(64), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("code_snippet", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("compliance_results", sa.JSON(), nullable=True),
        sa.Column("cwe_ids", sa.JSON(), nullable=True),
        sa.Column("owasp_category", sa.String(128), nullable=True),
        sa.Column("nist_control", sa.String(128), nullable=True),
        sa.Column("mitre_technique", sa.String(128), nullable=True),
        sa.Column("known_exploit", sa.Boolean(), nullable=False),
        sa.Column("references", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("scan_id", "severity", "cve_id", "status", "created_at"):
        op.create_index(f"ix_vulnerabilities_{column}", "vulnerabilities", [column])

    op.create_table(
        "cve_entries",
        sa.Column("cve_id", sa.String(64), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(128), nullable=True),
        sa.Column("severity", sa.String(32), nullable=True),
        sa.Column("published_date", sa.DateTime(), nullable=True),
        sa.Column("last_modified", sa.DateTime(), nullable=True),
        sa.Column("affected_software", sa.JSON(), nullable=True),
        sa.Column("references", sa.JSON(), nullable=True),
        sa.Column("known_exploits", sa.Boolean(), nullable=False),
        sa.Column("mitigation", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("cve_id"),
    )

    op.create_table(
        "ml_features",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("features_json", sa.JSON(), nullable=False),
        sa.Column("label", sa.String(64), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ml_features_scan_id", "ml_features", ["scan_id"])

    op.create_table(
        "notifications",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("is_read", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_notifications_user_id", "notifications", ["user_id"])
    op.create_index("ix_notifications_created_at", "notifications", ["created_at"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("resource", sa.String(128), nullable=False),
        sa.Column("resource_id", sa.String(128), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("ip_address", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])

    op.create_table(
        "compliance_checks",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("standard", sa.String(64), nullable=False),
        sa.Column("category", sa.String(128), nullable=True),
        sa.Column("result", sa.String(32), nullable=False),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_compliance_checks_scan_id", "compliance_checks", ["scan_id"])


def downgrade() -> None:
    for table in (
        "compliance_checks",
        "audit_logs",
        "notifications",
        "ml_features",
        "cve_entries",
        "vulnerabilities",
        "scan_files",
        "scans",
        "github_connections",
        "oauth_accounts",
        "users",
    ):
        op.drop_table(table)
