"""Initial Chaperone Phase 1 security schema: agents, tools, policies, audit_events.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-11-26 16:30:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001_initial_schema"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "agents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("key_id", sa.String(length=32), nullable=False),
        sa.Column("key_prefix", sa.String(length=32), nullable=False),
        sa.Column("api_key_hash", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
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
            "status IN ('active', 'disabled')", name=op.f("ck_agents_valid_agent_status")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agents")),
    )
    op.create_index(op.f("ix_agents_key_id"), "agents", ["key_id"], unique=True)
    op.create_index(op.f("ix_agents_name"), "agents", ["name"], unique=True)
    op.create_index(op.f("ix_agents_status"), "agents", ["status"], unique=False)

    op.create_table(
        "tools",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("risk_level", sa.String(length=16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
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
            "risk_level IN ('low', 'medium', 'high', 'critical')",
            name=op.f("ck_tools_valid_tool_risk_level"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tools")),
    )
    op.create_index(op.f("ix_tools_category"), "tools", ["category"], unique=False)
    op.create_index(op.f("ix_tools_enabled"), "tools", ["enabled"], unique=False)
    op.create_index(op.f("ix_tools_name"), "tools", ["name"], unique=True)

    op.create_table(
        "policies",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("agent_id", sa.Uuid(), nullable=True),
        sa.Column("tool_name", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("resource_scope", sa.String(length=512), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
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
            "decision IN ('allow', 'deny', 'require_approval')",
            name=op.f("ck_policies_valid_policy_decision"),
        ),
        sa.CheckConstraint(
            "priority >= 0 AND priority <= 10000", name=op.f("ck_policies_valid_policy_priority")
        ),
        sa.CheckConstraint("version >= 1", name=op.f("ck_policies_valid_policy_version")),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
            name=op.f("fk_policies_agent_id_agents"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tool_name"],
            ["tools.name"],
            name=op.f("fk_policies_tool_name_tools"),
            onupdate="CASCADE",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_policies")),
    )
    op.create_index(op.f("ix_policies_action"), "policies", ["action"], unique=False)
    op.create_index(op.f("ix_policies_agent_id"), "policies", ["agent_id"], unique=False)
    op.create_index(op.f("ix_policies_enabled"), "policies", ["enabled"], unique=False)
    op.create_index(
        "ix_policies_eval_lookup", "policies", ["tool_name", "enabled", "priority"], unique=False
    )
    op.create_index(op.f("ix_policies_name"), "policies", ["name"], unique=True)
    op.create_index(op.f("ix_policies_tool_name"), "policies", ["tool_name"], unique=False)

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("correlation_id", sa.String(length=64), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=True),
        sa.Column("tool_name", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("resource", sa.String(length=1024), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("policy_id", sa.Uuid(), nullable=True),
        sa.Column("policy_version", sa.Integer(), nullable=True),
        sa.Column(
            "policy_metadata",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=True,
        ),
        sa.Column("execution_status", sa.String(length=32), nullable=False),
        sa.Column("verification_status", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "decision IN ('allow', 'deny', 'require_approval')",
            name=op.f("ck_audit_events_valid_audit_decision"),
        ),
        sa.CheckConstraint(
            "execution_status IN ('not_executed', 'blocked', 'pending_approval')",
            name=op.f("ck_audit_events_valid_audit_execution_status"),
        ),
        sa.CheckConstraint(
            "verification_status IN ("
            "'verified', 'unauthenticated', 'invalid_credentials', "
            "'agent_disabled', 'tool_unavailable', 'validation_failed'"
            ")",
            name=op.f("ck_audit_events_valid_audit_verification_status"),
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
            name=op.f("fk_audit_events_agent_id_agents"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["policies.id"],
            name=op.f("fk_audit_events_policy_id_policies"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
    )
    op.create_index(op.f("ix_audit_events_agent_id"), "audit_events", ["agent_id"], unique=False)
    op.create_index(
        op.f("ix_audit_events_correlation_id"), "audit_events", ["correlation_id"], unique=False
    )
    op.create_index(
        op.f("ix_audit_events_created_at"), "audit_events", ["created_at"], unique=False
    )
    op.create_index(op.f("ix_audit_events_decision"), "audit_events", ["decision"], unique=False)
    op.create_index(op.f("ix_audit_events_policy_id"), "audit_events", ["policy_id"], unique=False)
    op.create_index(op.f("ix_audit_events_tool_name"), "audit_events", ["tool_name"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_audit_events_tool_name"), table_name="audit_events")
    op.drop_index(op.f("ix_audit_events_policy_id"), table_name="audit_events")
    op.drop_index(op.f("ix_audit_events_decision"), table_name="audit_events")
    op.drop_index(op.f("ix_audit_events_created_at"), table_name="audit_events")
    op.drop_index(op.f("ix_audit_events_correlation_id"), table_name="audit_events")
    op.drop_index(op.f("ix_audit_events_agent_id"), table_name="audit_events")
    op.drop_table("audit_events")

    op.drop_index(op.f("ix_policies_tool_name"), table_name="policies")
    op.drop_index(op.f("ix_policies_name"), table_name="policies")
    op.drop_index("ix_policies_eval_lookup", table_name="policies")
    op.drop_index(op.f("ix_policies_enabled"), table_name="policies")
    op.drop_index(op.f("ix_policies_agent_id"), table_name="policies")
    op.drop_index(op.f("ix_policies_action"), table_name="policies")
    op.drop_table("policies")

    op.drop_index(op.f("ix_tools_name"), table_name="tools")
    op.drop_index(op.f("ix_tools_enabled"), table_name="tools")
    op.drop_index(op.f("ix_tools_category"), table_name="tools")
    op.drop_table("tools")

    op.drop_index(op.f("ix_agents_status"), table_name="agents")
    op.drop_index(op.f("ix_agents_name"), table_name="agents")
    op.drop_index(op.f("ix_agents_key_id"), table_name="agents")
    op.drop_table("agents")
