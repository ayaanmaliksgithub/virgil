"""Routes for finding lifecycle — suppressions, baseline, diff.

Phase 4 §17 #4. Kept in its own module so it can grow (bulk suppress,
suppression import/export) without sprawling into findings.py.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Audit, FindingRow, Suppression
from app.db.session import get_db
from app.services.lifecycle import (
    active_suppressions,
    compute_audit_diff,
    resolve_baseline,
)
from app.services.triage_refresh import refresh_priority_list

router = APIRouter(tags=["lifecycle"])


class SuppressionIn(BaseModel):
    dedupe_key: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=2000)
    actor: str | None = Field(default=None, max_length=256)
    expires_at: datetime | None = None


class SuppressionOut(BaseModel):
    id: UUID
    source_ref: str
    dedupe_key: str
    reason: str
    actor: str | None
    expires_at: datetime | None
    created_at: datetime


class BaselineIn(BaseModel):
    baseline_audit_id: UUID | None


def _serialize_suppression(s: Suppression) -> dict:
    return {
        "id": str(s.id),
        "source_ref": s.source_ref,
        "dedupe_key": s.dedupe_key,
        "reason": s.reason,
        "actor": s.actor,
        "expires_at": s.expires_at.isoformat() if s.expires_at else None,
        "created_at": s.created_at.isoformat(),
    }


@router.post(
    "/v1/audits/{audit_id}/suppressions",
    status_code=status.HTTP_201_CREATED,
)
def create_suppression(audit_id: UUID, body: SuppressionIn, db: Session = Depends(get_db)) -> dict:
    audit = db.get(Audit, audit_id)
    if not audit:
        raise HTTPException(404, "Audit not found")

    # Validate the dedupe_key actually belongs to this audit so users can't
    # accidentally suppress findings they've never seen.
    exists = db.execute(
        select(FindingRow.id)
        .where(FindingRow.audit_id == audit_id, FindingRow.dedupe_key == body.dedupe_key)
        .limit(1)
    ).first()
    if not exists:
        raise HTTPException(400, "dedupe_key does not match any finding on this audit")

    sup = Suppression(
        source_ref=audit.source_ref,
        dedupe_key=body.dedupe_key,
        reason=body.reason,
        actor=body.actor,
        expires_at=body.expires_at,
    )
    db.add(sup)
    db.commit()
    db.refresh(sup)
    # Recompute the priority list so the suppressed cluster vanishes from
    # the top-K view. Deterministic re-rank, no LLM call.
    refresh_priority_list(db, audit)
    return _serialize_suppression(sup)


@router.get("/v1/audits/{audit_id}/suppressions")
def list_suppressions(audit_id: UUID, db: Session = Depends(get_db)) -> dict:
    audit = db.get(Audit, audit_id)
    if not audit:
        raise HTTPException(404, "Audit not found")
    active = active_suppressions(db, audit.source_ref)
    return {"items": [_serialize_suppression(s) for s in active.values()]}


@router.delete("/v1/suppressions/{suppression_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_suppression(suppression_id: UUID, db: Session = Depends(get_db)) -> None:
    sup = db.get(Suppression, suppression_id)
    if not sup:
        raise HTTPException(404, "Suppression not found")
    source_ref = sup.source_ref
    db.delete(sup)
    db.commit()
    # Find every audit that shares this source_ref and refresh its priority
    # list — un-suppressing should restore the cluster's position. Audits
    # for the same repo all draw from the same suppression set.
    affected = db.execute(
        select(Audit).where(Audit.source_ref == source_ref)
    ).scalars().all()
    for audit in affected:
        refresh_priority_list(db, audit)


@router.patch("/v1/audits/{audit_id}/baseline")
def set_baseline(audit_id: UUID, body: BaselineIn, db: Session = Depends(get_db)) -> dict:
    audit = db.get(Audit, audit_id)
    if not audit:
        raise HTTPException(404, "Audit not found")

    if body.baseline_audit_id is not None:
        if body.baseline_audit_id == audit_id:
            raise HTTPException(400, "baseline_audit_id cannot be the audit itself")
        baseline = db.get(Audit, body.baseline_audit_id)
        if not baseline:
            raise HTTPException(404, "Baseline audit not found")

    audit.baseline_audit_id = body.baseline_audit_id
    db.commit()
    return {"audit_id": str(audit.id), "baseline_audit_id": str(audit.baseline_audit_id) if audit.baseline_audit_id else None}


@router.get("/v1/audits/{audit_id}/diff")
def get_diff(
    audit_id: UUID,
    baseline: UUID | None = None,
    db: Session = Depends(get_db),
) -> dict:
    """Return new/recurring/resolved buckets vs. a baseline.

    `baseline` query param wins; otherwise falls back to the audit's stored
    `baseline_audit_id`. Returns 400 if no baseline is available either way.
    """
    audit = db.get(Audit, audit_id)
    if not audit:
        raise HTTPException(404, "Audit not found")

    baseline_id = baseline or audit.baseline_audit_id
    if baseline_id is None:
        raise HTTPException(400, "No baseline specified and audit has no baseline_audit_id")
    if baseline_id == audit_id:
        raise HTTPException(400, "Baseline cannot be the audit itself")
    baseline_audit = db.get(Audit, baseline_id)
    if not baseline_audit:
        raise HTTPException(404, "Baseline audit not found")

    buckets = compute_audit_diff(db, audit_id, baseline_id)
    return {
        "audit_id": str(audit_id),
        "baseline_audit_id": str(baseline_id),
        "summary": {
            "new": len(buckets.new),
            "recurring": len(buckets.recurring),
            "resolved": len(buckets.resolved),
        },
        "new": [_short(f) for f in buckets.new],
        "recurring": [_short(f) for f in buckets.recurring],
        "resolved": [_short(f) for f in buckets.resolved],
    }


def _short(f: FindingRow) -> dict:
    return {
        "id": str(f.id),
        "dedupe_key": f.dedupe_key,
        "title": f.title,
        "severity": f.severity,
        "category": f.category,
        "affected_files": f.affected_files,
    }
