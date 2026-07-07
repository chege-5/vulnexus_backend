"""Convert backend timestamp columns to timezone-aware UTC storage.

Revision ID: 20260704_utc_timestamps
Revises: None
Create Date: 2026-07-04
"""

from alembic import op
import sqlalchemy as sa


revision = "20260704_utc_timestamps"
down_revision = None
branch_labels = None
depends_on = None


_TIMESTAMP_COLUMNS = [
    ("users", "subscription_expires_at"),
    ("users", "trial_ends_at"),
    ("users", "last_login"),
    ("users", "created_at"),
    ("oauth_accounts", "expires_at"),
    ("oauth_accounts", "created_at"),
    ("github_connections", "connected_at"),
    ("github_connections", "last_synced_at"),
    ("scans", "queued_at"),
    ("scans", "started_at"),
    ("scans", "finished_at"),
    ("vulnerabilities", "created_at"),
    ("cve_entries", "published_date"),
    ("cve_entries", "last_modified"),
    ("notifications", "created_at"),
    ("audit_logs", "created_at"),
    ("compliance_checks", "created_at"),
]


def upgrade() -> None:
    for table_name, column_name in _TIMESTAMP_COLUMNS:
        op.alter_column(
            table_name,
            column_name,
            existing_type=sa.DateTime(timezone=False),
            type_=sa.DateTime(timezone=True),
            postgresql_using=f"{column_name} AT TIME ZONE 'UTC'",
            existing_nullable=True,
        )


def downgrade() -> None:
    for table_name, column_name in _TIMESTAMP_COLUMNS:
        op.alter_column(
            table_name,
            column_name,
            existing_type=sa.DateTime(timezone=True),
            type_=sa.DateTime(timezone=False),
            postgresql_using=f"{column_name} AT TIME ZONE 'UTC'",
            existing_nullable=True,
        )
