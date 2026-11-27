"""Phase 2 schema migration: approvals, verification, mock state, idempotency, audit extensions.

Revision ID: 0002_phase2_governance_execution
Revises: 0001_initial_schema
Create Date: 2026-11-26 17:10:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0002_phase2_governance_execution"
down_revision: str | Sequence[str] | None = "0001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "approval_requests",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("correlation_id", sa.String(length=64), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("tool_name", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("resource", sa.String(length=1024), nullable=False),
        sa.Column(
            "sanitized_arguments",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("policy_id", sa.Uuid(), nullable=True),
        sa.Column("policy_version", sa.Integer(), nullable=True),
        sa.Column("idempotency_key", sa.String(length=128), nullable=True),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewer_id", sa.String(length=128), nullable=True),
        sa.Column("reviewer_comment", sa.Text(), nullable=True),
        sa.Column("execution_claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "execution_result_reference",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=True,
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'expired', 'executed', 'failed')",
            name=op.f("ck_approval_requests_valid_approval_status"),
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
            name=op.f("fk_approval_requests_agent_id_agents"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["policies.id"],
            name=op.f("fk_approval_requests_policy_id_policies"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["tool_name"],
            ["tools.name"],
            name=op.f("fk_approval_requests_tool_name_tools"),
            onupdate="CASCADE",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_approval_requests")),
    )
    op.create_index(op.f("ix_approval_requests_agent_id"), "approval_requests", ["agent_id"])
    op.create_index(
        op.f("ix_approval_requests_correlation_id"), "approval_requests", ["correlation_id"]
    )
    op.create_index(op.f("ix_approval_requests_expires_at"), "approval_requests", ["expires_at"])
    op.create_index(
        op.f("ix_approval_requests_idempotency_key"), "approval_requests", ["idempotency_key"]
    )
    op.create_index(op.f("ix_approval_requests_policy_id"), "approval_requests", ["policy_id"])
    op.create_index(
        op.f("ix_approval_requests_requested_at"), "approval_requests", ["requested_at"]
    )
    op.create_index(op.f("ix_approval_requests_status"), "approval_requests", ["status"])
    op.create_index(op.f("ix_approval_requests_tool_name"), "approval_requests", ["tool_name"])

    with op.batch_alter_table("audit_events", schema=None) as batch_op:
        batch_op.drop_constraint(
            op.f("ck_audit_events_valid_audit_execution_status"), type_="check"
        )
        batch_op.drop_constraint(
            op.f("ck_audit_events_valid_audit_verification_status"), type_="check"
        )
        batch_op.add_column(
            sa.Column(
                "event_type",
                sa.String(length=64),
                server_default="policy_evaluation",
                nullable=False,
            )
        )
        batch_op.add_column(sa.Column("approval_id", sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column("reviewer_id", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("verification_outcome", sa.String(length=32), nullable=True))
        batch_op.add_column(
            sa.Column(
                "execution_metadata",
                sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
                nullable=True,
            )
        )
        batch_op.create_check_constraint(
            "valid_audit_execution_status",
            "execution_status IN ("
            "'not_executed', 'blocked', 'pending_approval', "
            "'started', 'executed', 'failed', 'rejected', 'expired'"
            ")",
        )
        batch_op.create_check_constraint(
            "valid_audit_verification_status",
            "verification_status IN ("
            "'verified', 'unauthenticated', 'invalid_credentials', "
            "'agent_disabled', 'tool_unavailable', 'validation_failed', "
            "'failed', 'inconclusive', 'not_applicable', "
            "'approved', 'rejected', 'expired'"
            ")",
        )
        batch_op.create_foreign_key(
            op.f("fk_audit_events_approval_id_approval_requests"),
            "approval_requests",
            ["approval_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(op.f("ix_audit_events_approval_id"), ["approval_id"])
        batch_op.create_index(op.f("ix_audit_events_event_type"), ["event_type"])

    op.create_table(
        "verification_records",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("correlation_id", sa.String(length=64), nullable=False),
        sa.Column("audit_event_id", sa.Uuid(), nullable=True),
        sa.Column("approval_id", sa.Uuid(), nullable=True),
        sa.Column("tool_name", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("resource", sa.String(length=1024), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("verification_method", sa.String(length=128), nullable=False),
        sa.Column(
            "expected_outcome",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "observed_outcome",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column(
            "verified_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('verified', 'failed', 'inconclusive', 'not_applicable')",
            name=op.f("ck_verification_records_valid_verification_outcome"),
        ),
        sa.ForeignKeyConstraint(
            ["approval_id"],
            ["approval_requests.id"],
            name=op.f("fk_verification_records_approval_id_approval_requests"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["audit_event_id"],
            ["audit_events.id"],
            name=op.f("fk_verification_records_audit_event_id_audit_events"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_verification_records")),
    )
    op.create_index(
        op.f("ix_verification_records_approval_id"), "verification_records", ["approval_id"]
    )
    op.create_index(
        op.f("ix_verification_records_audit_event_id"), "verification_records", ["audit_event_id"]
    )
    op.create_index(
        op.f("ix_verification_records_correlation_id"), "verification_records", ["correlation_id"]
    )
    op.create_index(op.f("ix_verification_records_status"), "verification_records", ["status"])
    op.create_index(
        op.f("ix_verification_records_tool_name"), "verification_records", ["tool_name"]
    )
    op.create_index(
        op.f("ix_verification_records_verified_at"), "verification_records", ["verified_at"]
    )

    op.create_table(
        "mock_emails",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("correlation_id", sa.String(length=64), nullable=False),
        sa.Column("recipient", sa.String(length=256), nullable=False),
        sa.Column("subject", sa.String(length=256), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("approval_id", sa.Uuid(), nullable=True),
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
            "status IN ('draft', 'sent', 'failed')",
            name=op.f("ck_mock_emails_valid_mock_email_status"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_mock_emails")),
    )
    op.create_index(op.f("ix_mock_emails_correlation_id"), "mock_emails", ["correlation_id"])
    op.create_index(op.f("ix_mock_emails_recipient"), "mock_emails", ["recipient"])
    op.create_index(op.f("ix_mock_emails_status"), "mock_emails", ["status"])

    op.create_table(
        "demo_invoices",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("invoice_number", sa.String(length=64), nullable=False),
        sa.Column("vendor_name", sa.String(length=128), nullable=False),
        sa.Column("amount_inr", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_demo_invoices")),
    )
    op.create_index(
        op.f("ix_demo_invoices_invoice_number"), "demo_invoices", ["invoice_number"], unique=True
    )

    op.create_table(
        "demo_tasks",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("owner", sa.String(length=128), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_demo_tasks")),
    )

    op.create_table(
        "execution_idempotency",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("response_status_code", sa.Integer(), nullable=False),
        sa.Column(
            "response_body",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
            name=op.f("fk_execution_idempotency_agent_id_agents"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_execution_idempotency")),
        sa.UniqueConstraint("agent_id", "idempotency_key", name="uq_exec_idempotency_agent_key"),
    )
    op.create_index(
        op.f("ix_execution_idempotency_agent_id"), "execution_idempotency", ["agent_id"]
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_execution_idempotency_agent_id"), table_name="execution_idempotency")
    op.drop_table("execution_idempotency")
    op.drop_table("demo_tasks")
    op.drop_index(op.f("ix_demo_invoices_invoice_number"), table_name="demo_invoices")
    op.drop_table("demo_invoices")
    op.drop_index(op.f("ix_mock_emails_status"), table_name="mock_emails")
    op.drop_index(op.f("ix_mock_emails_recipient"), table_name="mock_emails")
    op.drop_index(op.f("ix_mock_emails_correlation_id"), table_name="mock_emails")
    op.drop_table("mock_emails")
    op.drop_index(op.f("ix_verification_records_verified_at"), table_name="verification_records")
    op.drop_index(op.f("ix_verification_records_tool_name"), table_name="verification_records")
    op.drop_index(op.f("ix_verification_records_status"), table_name="verification_records")
    op.drop_index(op.f("ix_verification_records_correlation_id"), table_name="verification_records")
    op.drop_index(op.f("ix_verification_records_audit_event_id"), table_name="verification_records")
    op.drop_index(op.f("ix_verification_records_approval_id"), table_name="verification_records")
    op.drop_table("verification_records")

    with op.batch_alter_table("audit_events", schema=None) as batch_op:
        batch_op.drop_index(op.f("ix_audit_events_event_type"))
        batch_op.drop_index(op.f("ix_audit_events_approval_id"))
        batch_op.drop_constraint(
            op.f("fk_audit_events_approval_id_approval_requests"), type_="foreignkey"
        )
        batch_op.drop_constraint(
            op.f("ck_audit_events_valid_audit_verification_status"), type_="check"
        )
        batch_op.drop_constraint(
            op.f("ck_audit_events_valid_audit_execution_status"), type_="check"
        )
        batch_op.drop_column("execution_metadata")
        batch_op.drop_column("verification_outcome")
        batch_op.drop_column("reviewed_at")
        batch_op.drop_column("reviewer_id")
        batch_op.drop_column("approval_id")
        batch_op.drop_column("event_type")
        batch_op.create_check_constraint(
            "valid_audit_execution_status",
            "execution_status IN ('not_executed', 'blocked', 'pending_approval')",
        )
        batch_op.create_check_constraint(
            "valid_audit_verification_status",
            "verification_status IN ("
            "'verified', 'unauthenticated', 'invalid_credentials', "
            "'agent_disabled', 'tool_unavailable', 'validation_failed'"
            ")",
        )

    op.drop_index(op.f("ix_approval_requests_tool_name"), table_name="approval_requests")
    op.drop_index(op.f("ix_approval_requests_status"), table_name="approval_requests")
    op.drop_index(op.f("ix_approval_requests_requested_at"), table_name="approval_requests")
    op.drop_index(op.f("ix_approval_requests_policy_id"), table_name="approval_requests")
    op.drop_index(op.f("ix_approval_requests_idempotency_key"), table_name="approval_requests")
    op.drop_index(op.f("ix_approval_requests_expires_at"), table_name="approval_requests")
    op.drop_index(op.f("ix_approval_requests_correlation_id"), table_name="approval_requests")
    op.drop_index(op.f("ix_approval_requests_agent_id"), table_name="approval_requests")
    op.drop_table("approval_requests")
