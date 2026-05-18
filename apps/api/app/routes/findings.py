from __future__ import annotations

from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Audit, FindingRow
from app.db.session import get_db
from app.services.clusters import cluster_findings, serialize_cluster
from app.services.findings_export import build_csv, build_xlsx
from app.services.lifecycle import (
    active_suppressions,
    compute_audit_diff,
)

router = APIRouter(tags=["findings"])

Lifecycle = Literal["new", "recurring", "resolved"]


@router.get("/v1/audits/{audit_id}/findings")
def list_findings(
    audit_id: UUID,
    severity: list[str] | None = Query(default=None),
    category: list[str] | None = Query(default=None),
    owasp: list[str] | None = Query(default=None),
    file: str | None = Query(default=None),
    tool: list[str] | None = Query(default=None),
    confidence: list[str] | None = Query(default=None),
    include_suppressed: bool = Query(default=False),
    lifecycle: list[Lifecycle] | None = Query(default=None),
    baseline: UUID | None = Query(default=None),
    limit: int = Query(default=200, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> dict:
    audit = db.get(Audit, audit_id)
    if not audit:
        raise HTTPException(404, "Audit not found")

    stmt = select(FindingRow).where(FindingRow.audit_id == audit_id)
    if severity:
        stmt = stmt.where(FindingRow.severity.in_(severity))
    if category:
        stmt = stmt.where(FindingRow.category.in_(category))
    if owasp:
        stmt = stmt.where(FindingRow.owasp_category.in_(owasp))
    if confidence:
        stmt = stmt.where(FindingRow.confidence.in_(confidence))
    stmt = stmt.order_by(FindingRow.severity.desc(), FindingRow.created_at.desc())

    rows = db.execute(stmt).scalars().all()

    # Resolve lifecycle vs baseline (query param wins, else audit's stored baseline).
    baseline_id = baseline or audit.baseline_audit_id
    lifecycle_map: dict[str, str] = {}
    if baseline_id and baseline_id != audit_id:
        buckets = compute_audit_diff(db, audit_id, baseline_id)
        for f in buckets.new:
            lifecycle_map[f.dedupe_key] = "new"
        for f in buckets.recurring:
            lifecycle_map[f.dedupe_key] = "recurring"
        # `resolved` items don't appear in the current audit's rows by definition;
        # surface them via /diff, not the findings ledger.

    sup_map = active_suppressions(db, audit.source_ref)

    items = [_serialize(r, lifecycle_map.get(r.dedupe_key), sup_map.get(r.dedupe_key)) for r in rows]

    if not include_suppressed:
        items = [i for i in items if not i["suppressed"]]
    if lifecycle:
        wanted = set(lifecycle)
        items = [i for i in items if i.get("lifecycle") in wanted]
    if tool:
        items = [i for i in items if any(t in i["source_tool"] for t in tool)]
    if file:
        items = [i for i in items if any(file in af for af in i["affected_files"])]

    total = len(items)
    items = items[offset : offset + limit]
    return {
        "items": items,
        "limit": limit,
        "offset": offset,
        "total": total,
        "baseline_audit_id": str(baseline_id) if baseline_id else None,
    }


@router.get("/v1/audits/{audit_id}/findings/clusters")
def list_clusters(
    audit_id: UUID,
    include_unreachable: bool = Query(default=False),
    db: Session = Depends(get_db),
) -> dict:
    """Cluster findings by `(category, cwe, rule_signature)`.

    Defaults to hiding clusters whose every instance is unreachable — the
    same bias as the row view: unreachable deps are noise unless asked for.
    """
    audit = db.get(Audit, audit_id)
    if not audit:
        raise HTTPException(404, "Audit not found")
    rows = db.execute(
        select(FindingRow).where(FindingRow.audit_id == audit_id)
    ).scalars().all()
    clusters = cluster_findings(rows)
    if not include_unreachable:
        clusters = [c for c in clusters if not c.all_unreachable]

    # Join in the fix-the-helper hints stored on the audit profile.
    hints_map: dict = {}
    if isinstance(audit.profile, dict):
        hints_map = audit.profile.get("cluster_hints") or {}

    items = []
    for c in clusters:
        payload = serialize_cluster(c)
        if c.key in hints_map:
            payload["hint"] = hints_map[c.key]
        items.append(payload)
    return {
        "items": items,
        "total_findings": len(rows),
        "total_clusters": len(clusters),
    }


@router.get("/v1/audits/{audit_id}/findings/export")
def export_findings(
    audit_id: UUID,
    format: str = Query(default="csv", pattern="^(csv|xlsx)$"),
    db: Session = Depends(get_db),
):
    """Phase 5 #18 — CSV / XLSX export with stable column ordering."""
    audit = db.get(Audit, audit_id)
    if not audit:
        raise HTTPException(404, "Audit not found")
    rows = db.execute(
        select(FindingRow).where(FindingRow.audit_id == audit_id).order_by(
            FindingRow.severity.desc(), FindingRow.created_at.desc()
        )
    ).scalars().all()

    if format == "csv":
        return Response(
            content=build_csv(rows),
            media_type="text/csv",
            headers={"content-disposition": f'attachment; filename="audit-{audit_id}-findings.csv"'},
        )
    try:
        data = build_xlsx(rows)
    except RuntimeError as e:
        raise HTTPException(
            503,
            "XLSX export is not available on this deployment (openpyxl missing). Use format=csv.",
        ) from e
    return Response(
        content=data,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"content-disposition": f'attachment; filename="audit-{audit_id}-findings.xlsx"'},
    )


@router.get("/v1/findings/{finding_id}")
def get_finding(finding_id: UUID, db: Session = Depends(get_db)) -> dict:
    row = db.get(FindingRow, finding_id)
    if not row:
        raise HTTPException(404, "Finding not found")

    audit = db.get(Audit, row.audit_id)
    sup = None
    lifecycle_value: str | None = None
    if audit is not None:
        sup = active_suppressions(db, audit.source_ref).get(row.dedupe_key)
        baseline_id = audit.baseline_audit_id
        if baseline_id and baseline_id != audit.id:
            buckets = compute_audit_diff(db, audit.id, baseline_id)
            lifecycle_value = buckets.lifecycle_for(row.dedupe_key)
    return _serialize(row, lifecycle_value, sup)


def _serialize(r: FindingRow, lifecycle_value: str | None = None, suppression=None) -> dict:
    return {
        "id": str(r.id),
        "audit_id": str(r.audit_id),
        "dedupe_key": r.dedupe_key,
        "title": r.title,
        "severity": r.severity,
        "confidence": r.confidence,
        "category": r.category,
        "owasp_category": r.owasp_category,
        "cwe": r.cwe,
        "cve": r.cve,
        "affected_files": r.affected_files,
        "affected_lines": r.affected_lines,
        "evidence": r.evidence,
        "explanation": r.explanation,
        "exploitability_summary": r.exploitability_summary,
        "business_impact": r.business_impact,
        "safe_guidance": r.safe_guidance,
        "source_tool": r.source_tool,
        "raw_reference": r.raw_reference,
        "epss_score": r.epss_score,
        "epss_percentile": r.epss_percentile,
        "kev": bool(r.kev),
        "compliance": dict(getattr(r, "compliance", {}) or {}),
        "reachable": getattr(r, "reachable", None),
        "code_context": getattr(r, "code_context", None),
        "status": r.status,
        "lifecycle": lifecycle_value,
        "suppressed": suppression is not None,
        "suppression_reason": suppression.reason if suppression is not None else None,
        "suppression_id": str(suppression.id) if suppression is not None else None,
        "created_at": r.created_at.isoformat(),
    }
