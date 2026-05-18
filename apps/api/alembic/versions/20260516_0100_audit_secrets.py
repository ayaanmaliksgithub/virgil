"""audit secrets for private repository credentials

Revision ID: 0003_audit_secrets
Revises: 0002_chat
Create Date: 2026-05-16 01:00:00
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision: str = "0003_audit_secrets"
down_revision: Union[str, None] = "0002_chat"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_secrets",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("audit_id", UUID(as_uuid=True), sa.ForeignKey("audits.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("encrypted_value", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("audit_id", "kind", name="uq_audit_secrets_audit_kind"),
    )
    op.create_index("ix_audit_secrets_audit_id", "audit_secrets", ["audit_id"])


def downgrade() -> None:
    op.drop_index("ix_audit_secrets_audit_id", table_name="audit_secrets")
    op.drop_table("audit_secrets")
