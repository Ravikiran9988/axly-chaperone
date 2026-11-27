"""Phase 4 hardening migration: audit integrity record_hash and composite query indexes.

Revision ID: 0003_phase4_hardening_indexes
Revises: 0002_phase2_governance_execution
Create Date: 2026-11-27 16:10:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003_phase4_hardening_indexes"
down_revision: str | Sequence[str] | None = "0002_phase2_governance_execution"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("audit_events", schema=None) as batch_op:
        batch_op.add_column(sa.Column("record_hash", sa.String(length=64), nullable=True))

    op.create_index(
        "ix_audit_events_corr_created",
        "audit_events",
        ["correlation_id", "created_at"],
    )
    op.create_index(
        "ix_audit_events_agent_created",
        "audit_events",
        ["agent_id", "created_at"],
    )
    op.create_index(
        "ix_audit_events_type_verif",
        "audit_events",
        ["event_type", "verification_status"],
    )
    op.create_index(
        "ix_approval_requests_status_requested",
        "approval_requests",
        ["status", "requested_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_approval_requests_status_requested", table_name="approval_requests")
    op.drop_index("ix_audit_events_type_verif", table_name="audit_events")
    op.drop_index("ix_audit_events_agent_created", table_name="audit_events")
    op.drop_index("ix_audit_events_corr_created", table_name="audit_events")

    with op.batch_alter_table("audit_events", schema=None) as batch_op:
        batch_op.drop_column("record_hash")
