"""Tests for CSV/XLSX findings export (Phase 5 #18).

XLSX is opt-in (requires `openpyxl`); test is skipped when the dep isn't
present so the suite still runs on a stripped environment.
"""
from __future__ import annotations

import csv
import io
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

pytest.importorskip("pydantic")
pytest.importorskip("sqlalchemy")


@dataclass
class StubRow:
    id: UUID
    audit_id: UUID
    dedupe_key: str
    title: str
    severity: str
    confidence: str
    category: str
    owasp_category: str | None = None
    cwe: str | None = None
    cve: str | None = None
    affected_files: list[str] = field(default_factory=list)
    affected_lines: list[dict] = field(default_factory=list)
    evidence: str = ""
    explanation: str = ""
    exploitability_summary: str | None = None
    business_impact: str | None = None
    safe_guidance: str | None = None
    source_tool: list[str] = field(default_factory=lambda: ["semgrep"])
    raw_reference: dict = field(default_factory=dict)
    epss_score: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    compliance: dict = field(default_factory=dict)
    status: str = "open"
    created_at: datetime = field(default_factory=lambda: datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc))


def _row(**overrides) -> StubRow:
    base = dict(
        id=uuid4(),
        audit_id=uuid4(),
        dedupe_key="dk-1",
        title="Hard-coded secret",
        severity="High",
        confidence="High confidence",
        category="Secret Exposure",
        cwe="CWE-798",
        affected_files=["src/app.py", "src/util.py"],
        affected_lines=[{"file": "src/app.py", "start": 10, "end": 10}],
        source_tool=["gitleaks"],
    )
    base.update(overrides)
    return StubRow(**base)


def test_csv_has_stable_header_order():
    from app.services.findings_export import COLUMNS, build_csv

    data = build_csv([]).decode("utf-8")
    header = next(csv.reader(io.StringIO(data)))
    assert header == COLUMNS


def test_csv_row_serializes_lists_and_compliance():
    from app.services.findings_export import build_csv

    data = build_csv([_row(
        compliance={"SOC2": ["CC6.1"], "PCI-DSS": ["3.4", "8.2.1"]},
        kev=True,
    )]).decode("utf-8")
    rows = list(csv.DictReader(io.StringIO(data)))
    assert len(rows) == 1
    r = rows[0]
    assert r["affected_files"] == "src/app.py; src/util.py"
    assert r["affected_lines"] == "src/app.py:L10"
    assert r["kev"] == "yes"
    assert "SOC2:CC6.1" in r["compliance"]
    assert "PCI-DSS:3.4,8.2.1" in r["compliance"]


def test_csv_empty_fields_serialize_as_empty_strings():
    from app.services.findings_export import build_csv

    data = build_csv([_row(cve=None, kev=False, epss_score=None)]).decode("utf-8")
    r = next(csv.DictReader(io.StringIO(data)))
    assert r["cve"] == ""
    assert r["kev"] == ""
    assert r["epss_score"] == ""


def test_xlsx_round_trips_when_openpyxl_present():
    openpyxl = pytest.importorskip("openpyxl")
    from app.services.findings_export import build_xlsx, COLUMNS

    data = build_xlsx([_row()])
    wb = openpyxl.load_workbook(io.BytesIO(data))
    ws = wb.active
    header = [cell.value for cell in next(ws.iter_rows(max_row=1))]
    assert header == COLUMNS
    # Freeze pane is on row 2 so the header stays put when scrolling.
    assert ws.freeze_panes == "A2"


def test_xlsx_raises_runtime_error_when_openpyxl_missing(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "openpyxl", None)  # forces ImportError on next import
    from app.services.findings_export import build_xlsx

    with pytest.raises(RuntimeError, match="openpyxl"):
        build_xlsx([_row()])
