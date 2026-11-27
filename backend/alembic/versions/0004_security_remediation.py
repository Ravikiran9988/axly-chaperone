"""Phase 1 remediation migration: admin RBAC sessions and chained audit integrity.

Revision ID: 0004_security_remediation
Revises: 0003_phase4_hardening_indexes
Create Date: 2026-11-27 17:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004_security_remediation"
down_revision: str | Sequence[str] | None = "0003_phase4_hardening_indexes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "admin_users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "role IN ('super_admin', 'approver', 'viewer')",
            name="ck_admin_users_valid_admin_user_role",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'disabled')", name="ck_admin_users_valid_admin_user_status"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_admin_users"),
    )
    op.create_index("ix_admin_users_username", "admin_users", ["username"], unique=True)

    op.create_table(
        "admin_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("admin_user_id", sa.Uuid(), nullable=True),
        sa.Column("principal_id", sa.String(length=128), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("csrf_token", sa.String(length=128), nullable=False),
        sa.Column("auth_scheme", sa.String(length=32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["admin_user_id"],
            ["admin_users.id"],
            name="fk_admin_sessions_admin_user_id_admin_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_admin_sessions"),
    )
    op.create_index("ix_admin_sessions_admin_user_id", "admin_sessions", ["admin_user_id"])
    op.create_index("ix_admin_sessions_token_hash", "admin_sessions", ["token_hash"], unique=True)
    op.create_index(
        "ix_admin_sessions_expires_revoked",
        "admin_sessions",
        ["expires_at", "revoked_at"],
    )

    op.create_table(
        "audit_chain_state",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("last_seq", sa.Integer(), nullable=False),
        sa.Column("last_hash", sa.String(length=64), nullable=False),
        sa.Column("last_created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_chain_state"),
    )

    with op.batch_alter_table("audit_events", schema=None) as batch_op:
        batch_op.add_column(sa.Column("chain_seq", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("previous_hash", sa.String(length=64), nullable=True))

    op.create_index("ix_audit_events_chain_seq", "audit_events", ["chain_seq"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_audit_events_chain_seq", table_name="audit_events")
    with op.batch_alter_table("audit_events", schema=None) as batch_op:
        batch_op.drop_column("previous_hash")
        batch_op.drop_column("chain_seq")

    op.drop_table("audit_chain_state")
    op.drop_index("ix_admin_sessions_expires_revoked", table_name="admin_sessions")
    op.drop_index("ix_admin_sessions_token_hash", table_name="admin_sessions")
    op.drop_index("ix_admin_sessions_admin_user_id", table_name="admin_sessions")
    op.drop_table("admin_sessions")
    op.drop_index("ix_admin_users_username", table_name="admin_users")
    op.drop_table("admin_users")
