"""code_context column on findings

Revision ID: 0009_code_context
Revises: 0008_reachability
Create Date: 2026-05-17 05:00:00

Captures a redacted code slice around each finding's first affected line
so the chat retriever can ground answers in actual source code, not just
finding metadata.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0009_code_context"
down_revision: Union[str, None] = "0008_reachability"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("code_context", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "code_context")
