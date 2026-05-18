"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-05-15 20:00:00
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audits",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("source_kind", sa.String(16), nullable=False),
        sa.Column("source_ref", sa.Text(), nullable=False),
        sa.Column("sha", sa.String(64), nullable=True),
        sa.Column("state", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("phase", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("profile", JSONB, nullable=True),
    )
    op.create_index("ix_audits_state_phase", "audits", ["state", "phase"])

    op.create_table(
        "findings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("audit_id", UUID(as_uuid=True), sa.ForeignKey("audits.id", ondelete="CASCADE"), nullable=False),
        sa.Column("dedupe_key", sa.String(64), nullable=False),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(32), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("owasp_category", sa.String(128), nullable=True),
        sa.Column("cwe", sa.String(16), nullable=True),
        sa.Column("cve", sa.String(32), nullable=True),
        sa.Column("affected_files", JSONB, nullable=False),
        sa.Column("affected_lines", JSONB, nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("exploitability_summary", sa.Text(), nullable=True),
        sa.Column("business_impact", sa.Text(), nullable=True),
        sa.Column("safe_guidance", sa.Text(), nullable=True),
        sa.Column("source_tool", JSONB, nullable=False),
        sa.Column("raw_reference", JSONB, nullable=False, server_default="{}"),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_findings_audit_id", "findings", ["audit_id"])
    op.create_index("ix_findings_dedupe_key", "findings", ["dedupe_key"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_category", "findings", ["category"])
    op.create_index("ix_findings_owasp_category", "findings", ["owasp_category"])

    op.create_table(
        "job_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("audit_id", UUID(as_uuid=True), sa.ForeignKey("audits.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("phase", sa.String(16), nullable=False),
        sa.Column("level", sa.String(8), nullable=False, server_default="info"),
        sa.Column("message", sa.Text(), nullable=False),
    )
    op.create_index("ix_job_events_audit_id", "job_events", ["audit_id"])

    op.create_table(
        "reports",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("audit_id", UUID(as_uuid=True), sa.ForeignKey("audits.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),     # executive | technical
        sa.Column("format", sa.String(8), nullable=False),    # json | md | pdf
        sa.Column("uri", sa.Text(), nullable=False),          # s3://... or file://...
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_reports_audit_id", "reports", ["audit_id"])


def downgrade() -> None:
    op.drop_index("ix_reports_audit_id", table_name="reports")
    op.drop_table("reports")
    op.drop_index("ix_job_events_audit_id", table_name="job_events")
    op.drop_table("job_events")
    op.drop_index("ix_findings_owasp_category", table_name="findings")
    op.drop_index("ix_findings_category", table_name="findings")
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_dedupe_key", table_name="findings")
    op.drop_index("ix_findings_audit_id", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_audits_state_phase", table_name="audits")
    op.drop_table("audits")
