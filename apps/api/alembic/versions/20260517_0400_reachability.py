"""reachability column on findings

Revision ID: 0008_reachability
Revises: 0007_compliance
Create Date: 2026-05-17 04:00:00

Phase 4 §17 #8 — reachability. Nullable boolean: True/False meaningful only
for dependency findings; NULL means "not determined" (non-dep finding,
unsupported language, scanner didn't report a package name).
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0008_reachability"
down_revision: Union[str, None] = "0007_compliance"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("reachable", sa.Boolean(), nullable=True))
    op.create_index("ix_findings_reachable", "findings", ["reachable"])


def downgrade() -> None:
    op.drop_index("ix_findings_reachable", table_name="findings")
    op.drop_column("findings", "reachable")
