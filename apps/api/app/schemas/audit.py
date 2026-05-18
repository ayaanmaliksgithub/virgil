from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class CreateAuditRequest(BaseModel):
    """Used when submitting a GitHub URL. ZIP uploads use multipart form."""
    repo_url: str = Field(min_length=1, max_length=2048)
    github_token: str | None = Field(default=None, min_length=1, max_length=4096)
    # §17 #5 — PR-mode. Both must be set together; restricts findings to the
    # line-level diff between these SHAs. base_sha is the merge target,
    # head_sha is the PR tip.
    base_sha: str | None = Field(default=None, min_length=7, max_length=64, pattern=r"^[A-Fa-f0-9]+$")
    head_sha: str | None = Field(default=None, min_length=7, max_length=64, pattern=r"^[A-Fa-f0-9]+$")


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    source_kind: str
    source_ref: str
    state: str
    phase: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    profile: dict | None
    baseline_audit_id: UUID | None = None
    base_sha: str | None = None
    head_sha: str | None = None
