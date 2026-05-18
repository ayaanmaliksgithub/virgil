from __future__ import annotations

import json
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Audit, FindingRow, Report
from app.db.session import get_db
from app.services.reports import build_executive, build_technical, render_markdown
from app.services.sarif import build_sarif
from app.services.storage import get_report_bytes

router = APIRouter(prefix="/v1/audits", tags=["reports"])


@router.get("/{audit_id}/report")
def get_report(
    audit_id: UUID,
    view: str = Query(default="technical", pattern="^(executive|technical)$"),
    format: str = Query(default="json", pattern="^(json|md|pdf|sarif)$"),
    db: Session = Depends(get_db),
):
    audit = db.get(Audit, audit_id)
    if not audit:
        raise HTTPException(404, "Audit not found")

    # SARIF is finding-shaped, not narrative-shaped — no exec/tech split, no
    # stored artifact (it's cheap to render on demand). Build and return.
    if format == "sarif":
        findings = db.execute(select(FindingRow).where(FindingRow.audit_id == audit_id)).scalars().all()
        return Response(
            content=json.dumps(build_sarif(audit, findings), indent=2),
            media_type="application/sarif+json",
            headers={"content-disposition": f'attachment; filename="audit-{audit.id}.sarif"'},
        )

    stored = _stored_report(db, audit_id, view, format)
    if stored is not None:
        return stored

    findings = db.execute(select(FindingRow).where(FindingRow.audit_id == audit_id)).scalars().all()
    payload = build_executive(audit, findings) if view == "executive" else build_technical(audit, findings)

    if format == "json":
        return payload
    if format == "md":
        return Response(
            content=render_markdown(payload, view),
            media_type="text/markdown",
            headers={"content-disposition": f'attachment; filename="audit-{audit.id}-{view}.md"'},
        )
    # format == "pdf"
    try:
        from app.services.pdf import render_pdf
        pdf_bytes = render_pdf(payload, view)
    except RuntimeError as e:
        # WeasyPrint or its system deps are missing — keep the API up and tell
        # the caller to use a different format.
        raise HTTPException(
            status_code=503,
            detail="PDF rendering is not available on this deployment. Use format=md or format=json.",
        ) from e
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"content-disposition": f'attachment; filename="audit-{audit.id}-{view}.pdf"'},
    )


def _stored_report(db: Session, audit_id: UUID, view: str, fmt: str):
    row = db.execute(
        select(Report)
        .where(Report.audit_id == audit_id, Report.kind == view, Report.format == fmt)
        .order_by(Report.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    if row is None:
        return None

    try:
        body = get_report_bytes(row.uri)
    except Exception:
        # Stored artifacts are an optimization and immutable snapshot. If object
        # storage is unavailable or the object was removed, render live instead.
        return None

    if fmt == "json":
        return json.loads(body.decode("utf-8"))
    if fmt == "md":
        return Response(
            content=body,
            media_type="text/markdown",
            headers={"content-disposition": f'attachment; filename="audit-{audit_id}-{view}.md"'},
        )
    return Response(
        content=body,
        media_type="application/pdf",
        headers={"content-disposition": f'attachment; filename="audit-{audit_id}-{view}.pdf"'},
    )
