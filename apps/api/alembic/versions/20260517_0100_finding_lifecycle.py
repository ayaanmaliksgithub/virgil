"""finding lifecycle: suppressions + baseline_audit_id

Revision ID: 0005_finding_lifecycle
Revises: 0004_threat_intel
Create Date: 2026-05-17 01:00:00

Phase 4 #4 — finding lifecycle. Lets a re-scan of the same repo
compute new/recurring/resolved against a baseline, and lets a triager
suppress a finding (acknowledged-risk or false-positive) so it stops
clogging the default ledger view on the next scan.

Suppressions are keyed by `(source_ref, dedupe_key)` so they survive
re-scans of the same GitHub URL. For ZIP intakes, where each upload
gets a unique staged path as its source_ref, suppressions are
effectively single-audit — that's a deliberate simplification.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision: str = "0005_finding_lifecycle"
down_revision: Union[str, None] = "0004_threat_intel"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "suppressions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("source_ref", sa.Text(), nullable=False),
        sa.Column("dedupe_key", sa.String(64), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("actor", sa.String(256), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_suppressions_source_ref_dedupe", "suppressions", ["source_ref", "dedupe_key"])

    op.add_column(
        "audits",
        sa.Column(
            "baseline_audit_id",
            UUID(as_uuid=True),
            sa.ForeignKey("audits.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_audits_baseline_audit_id", "audits", ["baseline_audit_id"])


def downgrade() -> None:
    op.drop_index("ix_audits_baseline_audit_id", table_name="audits")
    op.drop_column("audits", "baseline_audit_id")
    op.drop_index("ix_suppressions_source_ref_dedupe", table_name="suppressions")
    op.drop_table("suppressions")
