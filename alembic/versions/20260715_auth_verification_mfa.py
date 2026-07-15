"""Add email verification and TOTP MFA state.

Revision ID: 20260715_auth_verification_mfa
Revises: 20260714_scan_result_metadata
Create Date: 2026-07-15
"""

from alembic import op
import sqlalchemy as sa


revision = "20260715_auth_verification_mfa"
down_revision = "20260714_scan_result_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column("users", sa.Column("email_verification_token_hash", sa.String(length=255), nullable=True))
    op.add_column("users", sa.Column("email_verification_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("users", sa.Column("mfa_secret", sa.Text(), nullable=True))
    op.add_column("users", sa.Column("mfa_recovery_codes", sa.JSON(), nullable=True))
    op.add_column("users", sa.Column("mfa_challenge_token_hash", sa.String(length=255), nullable=True))
    op.add_column("users", sa.Column("mfa_challenge_expires_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "mfa_challenge_expires_at")
    op.drop_column("users", "mfa_challenge_token_hash")
    op.drop_column("users", "mfa_recovery_codes")
    op.drop_column("users", "mfa_secret")
    op.drop_column("users", "mfa_enabled")
    op.drop_column("users", "email_verification_expires_at")
    op.drop_column("users", "email_verification_token_hash")
    op.drop_column("users", "email_verified")
