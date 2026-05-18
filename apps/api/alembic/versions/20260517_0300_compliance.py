"""compliance control mapping column on findings

Revision ID: 0007_compliance
Revises: 0006_pr_mode
Create Date: 2026-05-17 03:00:00

Phase 4 §17 #7 — per-finding compliance control mapping. Stored as JSONB
keyed by framework (`SOC2`, `PCI-DSS`, `HIPAA`, `ISO27001`) → list of
control IDs. Empty dict is the default; missing key means the framework
has no mapped controls for this finding's category/CWE.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0007_compliance"
down_revision: Union[str, None] = "0006_pr_mode"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("compliance", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    )


def downgrade() -> None:
    op.drop_column("findings", "compliance")
