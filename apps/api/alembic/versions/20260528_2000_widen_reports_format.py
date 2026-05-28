"""widen reports.format from VARCHAR(8) to VARCHAR(16)

Revision ID: 0010_widen_reports_format
Revises: 0009_code_context
Create Date: 2026-05-28 20:00:00

The reports.format column was VARCHAR(8), which fit the original `json` /
`html` / `pdf` / `sarif` set, but SBOM artifacts use 9-char `cyclonedx`
and `spdx-json` values that overflow on INSERT. Widen to VARCHAR(16) so
the report-artifact persistence step at the end of every audit succeeds.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0010_widen_reports_format"
down_revision: Union[str, None] = "0009_code_context"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "reports",
        "format",
        existing_type=sa.String(length=8),
        type_=sa.String(length=16),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "reports",
        "format",
        existing_type=sa.String(length=16),
        type_=sa.String(length=8),
        existing_nullable=False,
    )
