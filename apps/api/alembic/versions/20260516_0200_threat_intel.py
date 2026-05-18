"""threat intel table + EPSS/KEV columns on findings

Revision ID: 0004_threat_intel
Revises: 0003_audit_secrets
Create Date: 2026-05-16 02:00:00
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0004_threat_intel"
down_revision: Union[str, None] = "0003_audit_secrets"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "threat_intel",
        sa.Column("cve", sa.String(32), primary_key=True),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("kev", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("kev_added_date", sa.Date(), nullable=True),
        sa.Column("kev_due_date", sa.Date(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_threat_intel_kev", "threat_intel", ["kev"])

    op.add_column("findings", sa.Column("epss_score", sa.Float(), nullable=True))
    op.add_column("findings", sa.Column("epss_percentile", sa.Float(), nullable=True))
    op.add_column(
        "findings",
        sa.Column("kev", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_findings_kev", "findings", ["kev"])


def downgrade() -> None:
    op.drop_index("ix_findings_kev", table_name="findings")
    op.drop_column("findings", "kev")
    op.drop_column("findings", "epss_percentile")
    op.drop_column("findings", "epss_score")
    op.drop_index("ix_threat_intel_kev", table_name="threat_intel")
    op.drop_table("threat_intel")
