"""Finding lifecycle: baseline diff + suppression matching.

Phase 4 §17 #4. Two related concerns live here because they share the
same vocabulary — a `dedupe_key` identifies "the same finding" across
audits, so both "is this new since the baseline?" and "did someone
suppress this in the past?" answer by looking up that key.

Pure functions where possible so the diff buckets can be unit-tested
without spinning up Postgres.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Sequence
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Audit, FindingRow, Suppression


@dataclass(frozen=True)
class DiffBuckets:
    """Result of comparing a current audit against a baseline.

    Keys are dedupe_keys; values are lists of finding rows. `new` are
    findings present in current but not baseline; `recurring` are in
    both; `resolved` are in baseline but no longer in current.
    """
    new: list[FindingRow]
    recurring: list[FindingRow]
    resolved: list[FindingRow]

    def lifecycle_for(self, dedupe_key: str) -> str | None:
        if any(f.dedupe_key == dedupe_key for f in self.new):
            return "new"
        if any(f.dedupe_key == dedupe_key for f in self.recurring):
            return "recurring"
        if any(f.dedupe_key == dedupe_key for f in self.resolved):
            return "resolved"
        return None


def diff_against_baseline(
    current: Sequence[FindingRow], baseline: Sequence[FindingRow]
) -> DiffBuckets:
    """Pure diff over two finding sequences. No DB access."""
    baseline_by_key = {f.dedupe_key: f for f in baseline}
    current_keys = {f.dedupe_key for f in current}

    new: list[FindingRow] = []
    recurring: list[FindingRow] = []
    for f in current:
        if f.dedupe_key in baseline_by_key:
            recurring.append(f)
        else:
            new.append(f)
    resolved = [f for k, f in baseline_by_key.items() if k not in current_keys]
    return DiffBuckets(new=new, recurring=recurring, resolved=resolved)


def compute_audit_diff(db: Session, audit_id: UUID, baseline_id: UUID) -> DiffBuckets:
    """DB-backed diff between two audits."""
    current = list(db.execute(select(FindingRow).where(FindingRow.audit_id == audit_id)).scalars())
    baseline = list(db.execute(select(FindingRow).where(FindingRow.audit_id == baseline_id)).scalars())
    return diff_against_baseline(current, baseline)


def active_suppressions(
    db: Session, source_ref: str, *, now: datetime | None = None
) -> dict[str, Suppression]:
    """Return the active suppressions for a repo source_ref, keyed by dedupe_key.

    Expired suppressions (`expires_at <= now`) are filtered out. When two
    suppressions share a dedupe_key (re-suppressed after expiry, say), the
    most-recent wins so the UI shows the latest reason.
    """
    now = now or datetime.now(timezone.utc)
    rows = db.execute(
        select(Suppression)
        .where(Suppression.source_ref == source_ref)
        .order_by(Suppression.created_at.desc())
    ).scalars()
    out: dict[str, Suppression] = {}
    for s in rows:
        if s.expires_at is not None and s.expires_at <= now:
            continue
        out.setdefault(s.dedupe_key, s)
    return out


def suppression_keys(
    db: Session, source_ref: str, *, now: datetime | None = None
) -> set[str]:
    """Convenience: just the suppressed dedupe_keys."""
    return set(active_suppressions(db, source_ref, now=now).keys())


def resolve_baseline(db: Session, audit: Audit) -> Audit | None:
    """Return the baseline audit row, or None if no baseline or it's missing."""
    if audit.baseline_audit_id is None:
        return None
    return db.get(Audit, audit.baseline_audit_id)


def autoselect_baseline(db: Session, audit: Audit) -> Audit | None:
    """Pick the most recent prior succeeded audit for the same source_ref.

    Used when the worker finishes an audit and no explicit baseline was set —
    the natural baseline is the previous successful scan of the same repo.
    `source_kind=zip` audits get unique source_refs per upload so this
    correctly returns None for them.
    """
    stmt = (
        select(Audit)
        .where(
            Audit.source_ref == audit.source_ref,
            Audit.id != audit.id,
            Audit.state == "succeeded",
            Audit.created_at < audit.created_at,
        )
        .order_by(Audit.created_at.desc())
        .limit(1)
    )
    return db.execute(stmt).scalar_one_or_none()
