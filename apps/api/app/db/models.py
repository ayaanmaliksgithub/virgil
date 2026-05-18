from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import Boolean, Date, Float, ForeignKey, String, Text, Integer, DateTime, JSON, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Audit(Base):
    __tablename__ = "audits"
    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    source_kind: Mapped[str] = mapped_column(String(16))  # 'url' | 'zip'
    source_ref: Mapped[str] = mapped_column(Text)
    sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    state: Mapped[str] = mapped_column(String(16), default="pending")
    phase: Mapped[str] = mapped_column(String(16), default="queued")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    profile: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # §17 #5 — PR-mode scanning. When both are set, the worker post-filters
    # findings to those whose affected_lines intersect the line-level diff
    # between these two SHAs.
    base_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    head_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # §17 #4 — points at a prior audit to diff against. Re-scans of the same repo
    # set this so the findings ledger can render new/recurring/resolved buckets.
    baseline_audit_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("audits.id", ondelete="SET NULL"), nullable=True, index=True
    )

    findings: Mapped[list["FindingRow"]] = relationship(back_populates="audit", cascade="all,delete-orphan")
    events: Mapped[list["JobEvent"]] = relationship(back_populates="audit", cascade="all,delete-orphan")
    secrets: Mapped[list["AuditSecret"]] = relationship(back_populates="audit", cascade="all,delete-orphan")


class AuditSecret(Base):
    __tablename__ = "audit_secrets"
    __table_args__ = (UniqueConstraint("audit_id", "kind", name="uq_audit_secrets_audit_kind"),)

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    audit_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("audits.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    encrypted_value: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    audit: Mapped[Audit] = relationship(back_populates="secrets")


class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    audit_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("audits.id", ondelete="CASCADE"), index=True)
    dedupe_key: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(256))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[str] = mapped_column(String(32))
    category: Mapped[str] = mapped_column(String(64), index=True)
    owasp_category: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    cwe: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cve: Mapped[str | None] = mapped_column(String(32), nullable=True)
    affected_files: Mapped[list] = mapped_column(JSONB)
    affected_lines: Mapped[list] = mapped_column(JSONB)
    evidence: Mapped[str] = mapped_column(Text)
    explanation: Mapped[str] = mapped_column(Text)
    exploitability_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    business_impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    safe_guidance: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_tool: Mapped[list] = mapped_column(JSONB)
    raw_reference: Mapped[dict] = mapped_column(JSONB, default=dict)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    compliance: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    reachable: Mapped[bool | None] = mapped_column(Boolean, nullable=True, index=True)
    code_context: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    audit: Mapped[Audit] = relationship(back_populates="findings")


class JobEvent(Base):
    __tablename__ = "job_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("audits.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    phase: Mapped[str] = mapped_column(String(16))
    level: Mapped[str] = mapped_column(String(8), default="info")
    message: Mapped[str] = mapped_column(Text)

    audit: Mapped[Audit] = relationship(back_populates="events")


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    audit_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("audits.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16))      # executive | technical
    format: Mapped[str] = mapped_column(String(8))     # json | md | pdf
    uri: Mapped[str] = mapped_column(Text)             # s3://... or file://...
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ChatSession(Base):
    __tablename__ = "chat_sessions"
    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    audit_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("audits.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    messages: Mapped[list["ChatMessage"]] = relationship(back_populates="session", cascade="all,delete-orphan")


class ThreatIntel(Base):
    """Per-CVE threat-intel snapshot, refreshed nightly from EPSS + CISA KEV.

    Keyed by CVE so normalization can join on `findings.cve`. Rows are upserted
    by the daily worker.tasks.refresh_threat_intel task; absence of a row means
    "not in either feed" — never assume a default score.
    """
    __tablename__ = "threat_intel"

    cve: Mapped[str] = mapped_column(String(32), primary_key=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    kev_added_date: Mapped["datetime | None"] = mapped_column(Date, nullable=True)  # type: ignore[name-defined]
    kev_due_date: Mapped["datetime | None"] = mapped_column(Date, nullable=True)  # type: ignore[name-defined]
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class Suppression(Base):
    """§17 #4 — acknowledged-risk / false-positive suppression for a finding.

    Keyed by (`source_ref`, `dedupe_key`) so the suppression survives re-scans of
    the same repo URL. For ZIP audits — where each upload becomes a unique staged
    path — suppressions only match within that one audit, which is fine: a ZIP
    audit is a one-shot.
    """
    __tablename__ = "suppressions"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    source_ref: Mapped[str] = mapped_column(Text, index=True)
    dedupe_key: Mapped[str] = mapped_column(String(64), index=True)
    reason: Mapped[str] = mapped_column(Text)
    actor: Mapped[str | None] = mapped_column(String(256), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ChatMessage(Base):
    __tablename__ = "chat_messages"
    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    session_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("chat_sessions.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(16))      # user | assistant
    content: Mapped[str] = mapped_column(Text)
    citations: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    session: Mapped[ChatSession] = relationship(back_populates="messages")
