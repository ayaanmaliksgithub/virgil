"""pr-mode columns on audits

Revision ID: 0006_pr_mode
Revises: 0005_finding_lifecycle
Create Date: 2026-05-17 02:00:00

Phase 4 #5 — diff/PR-mode scanning. The audit row records the SHAs
that bracket the diff so the worker can intersect findings with the
changed line ranges. Both nullable: PR-mode is opt-in.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0006_pr_mode"
down_revision: Union[str, None] = "0005_finding_lifecycle"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("audits", sa.Column("base_sha", sa.String(64), nullable=True))
    op.add_column("audits", sa.Column("head_sha", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("audits", "head_sha")
    op.drop_column("audits", "base_sha")
