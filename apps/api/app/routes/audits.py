from __future__ import annotations

from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import Audit
from app.db.session import get_db
from app.schemas.audit import AuditOut, CreateAuditRequest
from app.services.intake import IntakeError, create_audit_from_url, create_audit_from_zip
from app.services.queue import enqueue_audit

router = APIRouter(prefix="/v1/audits", tags=["audits"])

STAGING_DIR = Path("/var/audit/uploads")


@router.post("", response_model=AuditOut, status_code=status.HTTP_201_CREATED)
async def create_audit(
    repo_url: str | None = Form(default=None),
    github_token: str | None = Form(default=None),
    file: UploadFile | None = File(default=None),
    db: Session = Depends(get_db),
) -> Audit:
    if (repo_url is None) == (file is None):
        raise HTTPException(400, "Provide exactly one of: repo_url, file")

    try:
        if repo_url:
            audit = create_audit_from_url(db, repo_url, github_token=github_token)
        else:
            assert file is not None
            if github_token:
                raise IntakeError("Private repository tokens are only valid with repo_url submissions")
            audit = await create_audit_from_zip(db, file, STAGING_DIR)
    except IntakeError as e:
        raise HTTPException(400, str(e)) from e

    enqueue_audit(str(audit.id))
    return audit


@router.post("/json", response_model=AuditOut, status_code=status.HTTP_201_CREATED)
def create_audit_from_json(body: CreateAuditRequest, db: Session = Depends(get_db)) -> Audit:
    """JSON-only URL submission (convenience)."""
    try:
        audit = create_audit_from_url(
            db,
            body.repo_url,
            github_token=body.github_token,
            base_sha=body.base_sha,
            head_sha=body.head_sha,
        )
    except IntakeError as e:
        raise HTTPException(400, str(e)) from e
    enqueue_audit(str(audit.id))
    return audit


@router.get("/{audit_id}", response_model=AuditOut)
def get_audit(audit_id: UUID, db: Session = Depends(get_db)) -> Audit:
    audit = db.get(Audit, audit_id)
    if not audit:
        raise HTTPException(404, "Audit not found")
    return audit


@router.get("/{audit_id}/queue")
def get_queue_status(audit_id: UUID, db: Session = Depends(get_db)) -> dict:
    """Queue-position snapshot for the audit console's pre-scan UX.

    Returns a small dict suitable for polling every few seconds while a
    submitted job is `pending` or still in the `cloning` phase:

      `{ state, phase, active, position?, ahead?, in_flight? }`

    `active=True` means the queue panel should remain visible. The frontend
    hides it once `active=False` (terminal state, or running past cloning),
    handing the UI off to the live console stream.

    Position is 1-indexed: position=1 means "you're next". Audits that are
    already `running` report position=0; terminal audits omit position.
    """
    audit = db.get(Audit, audit_id)
    if not audit:
        raise HTTPException(404, "Audit not found")

    common = {"state": audit.state, "phase": audit.phase}

    if audit.state in ("succeeded", "failed"):
        return {**common, "active": False}

    in_flight = int(db.execute(
        select(func.count(Audit.id)).where(Audit.state == "running")
    ).scalar() or 0)

    if audit.state == "running":
        # Still surface in_flight so the user sees they're the one running,
        # but only treat the queue UI as "active" while we're in the pre-scan
        # phases. Once scanning starts, the console stream owns the UI.
        active = audit.phase in ("queued", "cloning")
        return {**common, "active": active, "position": 0, "ahead": 0, "in_flight": in_flight}

    # pending — count audits queued ahead of us by creation time.
    ahead = int(db.execute(
        select(func.count(Audit.id)).where(
            Audit.state == "pending",
            Audit.created_at < audit.created_at,
        )
    ).scalar() or 0)
    return {
        **common,
        "active": True,
        "position": ahead + 1,
        "ahead": ahead,
        "in_flight": in_flight,
    }
