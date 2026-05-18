"""Regression tests for the three review bugs found after the initial
EPSS/KEV pass:

1. `_persist_findings` dropped `epss_score / epss_percentile / kev` when
   building `FindingRow` from `Finding` → DB rows had null/null/false even
   when correlation produced enrichment.
2. The findings list/detail JSON serializer omitted the three fields →
   API consumers couldn't read them.
3. `reports.build_technical` + `render_markdown` omitted them → the
   technical report (JSON and Markdown) hid the threat intel.
4. `chat._row_to_finding` rebuilt `Finding` without the fields → the
   chat retriever's per-finding context lost them.

Each test isolates a single serialization boundary with an in-memory stand-in
for `FindingRow`, so we don't need Postgres to lock these regressions down.
"""
from __future__ import annotations

import os
# Point the API's lazy-loaded engine at SQLite-in-memory so importing
# `app.routes.findings` etc. doesn't require psycopg or a real Postgres.
# We never run queries against it — only the route helper functions are
# exercised, with hand-built stub rows.
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import types
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

pytest.importorskip("pydantic")
pytest.importorskip("sqlalchemy")

# We import the route/service helpers lazily inside each accessor — FastAPI's
# import graph is heavy and we only need the pure functions here.

def _serializer():
    from app.routes.findings import _serialize
    return _serialize


def _row_to_finding():
    from app.routes.chat import _row_to_finding as fn
    return fn


def _build_tech():
    from app.services.reports import build_technical, render_markdown
    return build_technical, render_markdown


@dataclass
class StubFindingRow:
    id: UUID
    audit_id: UUID
    dedupe_key: str
    title: str
    severity: str
    confidence: str
    category: str
    owasp_category: str | None
    cwe: str | None
    cve: str | None
    affected_files: list
    affected_lines: list
    evidence: str
    explanation: str
    exploitability_summary: str | None
    business_impact: str | None
    safe_guidance: str | None
    source_tool: list
    raw_reference: dict
    epss_score: float | None
    epss_percentile: float | None
    kev: bool
    status: str
    created_at: datetime


def _row(**overrides) -> StubFindingRow:
    base = dict(
        id=uuid4(),
        audit_id=uuid4(),
        dedupe_key="dk",
        title="Demo finding",
        severity="High",
        confidence="High confidence",
        category="Vulnerable Dependency",
        owasp_category=None,
        cwe=None,
        cve="CVE-2024-1234",
        affected_files=["package.json"],
        affected_lines=[{"file": "package.json", "start": 1, "end": None}],
        evidence="redacted",
        explanation="dep CVE",
        exploitability_summary=None,
        business_impact=None,
        safe_guidance=None,
        source_tool=["trivy"],
        raw_reference={},
        epss_score=0.91,
        epss_percentile=0.99,
        kev=True,
        status="open",
        created_at=datetime.now(timezone.utc),
    )
    base.update(overrides)
    return StubFindingRow(**base)


# -- bug #3a: findings list / detail serializer ------------------------------

def test_findings_serializer_includes_threat_intel_fields():
    serialize = _serializer()
    out = serialize(_row())
    assert out["epss_score"] == pytest.approx(0.91)
    assert out["epss_percentile"] == pytest.approx(0.99)
    assert out["kev"] is True


def test_findings_serializer_handles_null_threat_intel():
    serialize = _serializer()
    out = serialize(_row(epss_score=None, epss_percentile=None, kev=False))
    assert out["epss_score"] is None
    assert out["epss_percentile"] is None
    assert out["kev"] is False


# -- bug #3b: technical report JSON + Markdown -------------------------------

def test_technical_report_json_includes_threat_intel():
    build_technical, _ = _build_tech()
    audit = types.SimpleNamespace(
        id=uuid4(), source_kind="url", source_ref="https://github.com/example/repo",
        sha=None, finished_at=None, profile=None,
    )
    findings = [_row(severity="High"), _row(severity="Low", kev=False, epss_score=0.001, epss_percentile=0.1)]
    payload = build_technical(audit, findings)
    assert "findings" in payload
    f0 = payload["findings"][0]
    assert "epss_score" in f0 and "epss_percentile" in f0 and "kev" in f0
    # KEV+EPSS pass through with the right types
    assert isinstance(f0["kev"], bool)


def test_technical_markdown_renders_kev_and_epss_lines():
    build_technical, render_markdown = _build_tech()
    audit = types.SimpleNamespace(
        id=uuid4(), source_kind="url", source_ref="https://github.com/example/repo",
        sha=None, finished_at=None, profile=None,
    )
    payload = build_technical(audit, [_row(severity="High", kev=True, epss_score=0.93, epss_percentile=0.99)])
    md = render_markdown(payload, view="technical")
    assert "**CISA KEV:**" in md
    assert "known exploited in the wild" in md
    assert "**EPSS:** 0.9300" in md
    assert "percentile 0.99" in md


def test_technical_markdown_omits_threat_intel_lines_when_null():
    build_technical, render_markdown = _build_tech()
    audit = types.SimpleNamespace(
        id=uuid4(), source_kind="url", source_ref="https://github.com/example/repo",
        sha=None, finished_at=None, profile=None,
    )
    payload = build_technical(audit, [_row(severity="Medium", kev=False, epss_score=None, epss_percentile=None)])
    md = render_markdown(payload, view="technical")
    assert "CISA KEV" not in md
    assert "EPSS:" not in md


# -- bug #3c: chat _row_to_finding -------------------------------------------

def test_chat_row_to_finding_preserves_threat_intel():
    fn = _row_to_finding()
    finding = fn(_row())
    assert finding.epss_score == pytest.approx(0.91)
    assert finding.epss_percentile == pytest.approx(0.99)
    assert finding.kev is True


# -- bug #2: persistence round-trip ------------------------------------------
# We can't drive the real SQLAlchemy bulk_save_objects in unit tests, but we
# can assert that the function builds FindingRow with the three fields set.
# The previous code path silently dropped them — this test pins the contract.

def test_persist_findings_copies_threat_intel_onto_findingrow(monkeypatch):
    from audit_core import AffectedLine, Confidence, Finding, Severity, Status

    from worker import tasks

    f = Finding(
        dedupe_key="k",
        title="Demo",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="Vulnerable Dependency",
        cve="CVE-2024-1234",
        affected_files=["package.json"],
        affected_lines=[AffectedLine(file="package.json", start=1)],
        evidence="redacted",
        explanation="dep CVE",
        source_tool=["trivy"],
        epss_score=0.91,
        epss_percentile=0.99,
        kev=True,
        status=Status.OPEN,
    )

    captured: list = []

    class FakeSession:
        def bulk_save_objects(self, rows):
            captured.extend(rows)
        def commit(self):
            pass

    audit = types.SimpleNamespace(id=uuid4())
    rows = tasks._persist_findings(FakeSession(), audit, [f])

    assert len(rows) == 1
    row = rows[0]
    assert row.epss_score == pytest.approx(0.91)
    assert row.epss_percentile == pytest.approx(0.99)
    assert row.kev is True
