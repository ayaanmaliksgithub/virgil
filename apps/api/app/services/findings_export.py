"""CSV / XLSX export of findings (Phase 5 #18).

Stable column ordering — security teams paste these into spreadsheets,
and a column shuffle between scans is the kind of papercut that erodes
trust fast. If you must add a column, append it; do not reorder.

XLSX support is optional: if `openpyxl` is missing on the host the
route returns HTTP 503 the same way PDF does, so the API stays up.
"""
from __future__ import annotations

import csv
import io
from typing import Iterable

from app.db.models import FindingRow

# Canonical column order. Append-only.
COLUMNS = [
    "id",
    "audit_id",
    "title",
    "severity",
    "confidence",
    "category",
    "owasp_category",
    "cwe",
    "cve",
    "kev",
    "epss_score",
    "epss_percentile",
    "compliance",
    "affected_files",
    "affected_lines",
    "source_tool",
    "status",
    "dedupe_key",
    "created_at",
]


def _row_dict(f: FindingRow) -> dict:
    """Flatten a FindingRow into spreadsheet-friendly values."""
    return {
        "id": str(f.id),
        "audit_id": str(f.audit_id),
        "title": f.title,
        "severity": f.severity,
        "confidence": f.confidence,
        "category": f.category,
        "owasp_category": f.owasp_category or "",
        "cwe": f.cwe or "",
        "cve": f.cve or "",
        "kev": "yes" if getattr(f, "kev", False) else "",
        "epss_score": f.epss_score if f.epss_score is not None else "",
        "epss_percentile": f.epss_percentile if f.epss_percentile is not None else "",
        "compliance": "; ".join(
            f"{k}:{','.join(v)}" for k, v in sorted((getattr(f, "compliance", {}) or {}).items()) if v
        ),
        "affected_files": "; ".join(f.affected_files or []),
        "affected_lines": "; ".join(
            f"{(al.get('file') if isinstance(al, dict) else getattr(al, 'file', ''))}"
            f":L{(al.get('start') if isinstance(al, dict) else getattr(al, 'start', ''))}"
            for al in (f.affected_lines or [])
        ),
        "source_tool": "; ".join(f.source_tool or []),
        "status": f.status,
        "dedupe_key": f.dedupe_key,
        "created_at": f.created_at.isoformat() if f.created_at else "",
    }


def build_csv(findings: Iterable[FindingRow]) -> bytes:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    for f in findings:
        writer.writerow(_row_dict(f))
    return buf.getvalue().encode("utf-8")


def build_xlsx(findings: Iterable[FindingRow]) -> bytes:
    """Render an XLSX. Raises RuntimeError if openpyxl is unavailable."""
    try:
        from openpyxl import Workbook
    except ImportError as e:  # noqa: F841
        raise RuntimeError("openpyxl is not installed") from e

    wb = Workbook()
    ws = wb.active
    ws.title = "findings"
    ws.append(COLUMNS)
    for f in findings:
        row = _row_dict(f)
        ws.append([row[c] for c in COLUMNS])

    # Freeze the header row so the spreadsheet scrolls cleanly.
    ws.freeze_panes = "A2"

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()
