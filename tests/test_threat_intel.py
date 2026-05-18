"""Tests for the EPSS / CISA KEV threat-intel pipeline (Phase 4, item #2).

Covers:
- parse_epss_csv: handles gzipped + plain, ignores comments/headers/bad rows
- parse_kev_json: extracts CVEs + dates, ignores malformed entries
- enrich_with_threat_intel: attaches scores when the row exists, no-ops cleanly
  when the row is missing or lookup errors

The HTTP fetch + Postgres upsert paths aren't exercised here — they need a real
DB and live feeds. They're covered indirectly by the compose smoke test and by
manual `celery call worker.tasks.refresh_threat_intel` runs.
"""
from __future__ import annotations

import gzip
import json

import pytest

pytest.importorskip("pydantic")

from audit_core import (
    AffectedLine,
    Confidence,
    Finding,
    Severity,
    Status,
)

from worker.normalize.threat_intel import enrich_with_threat_intel
from worker.threat_intel import parse_epss_csv, parse_kev_json


def _mk_finding(cve: str | None) -> Finding:
    return Finding(
        dedupe_key=f"k:{cve or 'none'}",
        title="Demo finding",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="Vulnerable Dependency",
        cve=cve,
        affected_files=["package.json"],
        affected_lines=[AffectedLine(file="package.json", start=1)],
        evidence="redacted",
        explanation="dep CVE",
        source_tool=["trivy"],
        status=Status.OPEN,
    )


# -- parse_epss_csv -----------------------------------------------------------

def test_parse_epss_csv_plain_text():
    csv = (
        "#model_version:v2025.03.14,score_date:2026-05-15T00:00:00+0000\n"
        "cve,epss,percentile\n"
        "CVE-2024-1234,0.97231,0.99821\n"
        "CVE-2023-5555,0.00012,0.21340\n"
    ).encode("utf-8")

    rows = parse_epss_csv(csv)

    assert len(rows) == 2
    assert rows[0].cve == "CVE-2024-1234"
    assert rows[0].score == pytest.approx(0.97231)
    assert rows[0].percentile == pytest.approx(0.99821)


def test_parse_epss_csv_gzipped():
    raw = b"cve,epss,percentile\nCVE-2024-0001,0.1,0.5\n"
    rows = parse_epss_csv(gzip.compress(raw))
    assert [r.cve for r in rows] == ["CVE-2024-0001"]


def test_parse_epss_csv_skips_garbage_rows():
    csv = (
        "cve,epss,percentile\n"
        "CVE-2024-1234,0.5,0.6\n"
        "not-a-cve,0.1,0.2\n"
        "CVE-2024-9999,oops,0.1\n"           # bad score
        "CVE-2024-8888,1.5,0.4\n"             # out of range
        ",,,\n"
        "CVE-2024-7777,0.42,0.5\n"
    ).encode("utf-8")

    cves = [r.cve for r in parse_epss_csv(csv)]
    assert cves == ["CVE-2024-1234", "CVE-2024-7777"]


# -- parse_kev_json -----------------------------------------------------------

def test_parse_kev_json_happy_path():
    payload = json.dumps({
        "title": "CISA KEV",
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-1234",
                "vendorProject": "Acme",
                "dateAdded": "2024-03-04",
                "dueDate": "2024-03-25",
            },
            {
                "cveID": "CVE-2023-9999",
                "dateAdded": "2023-11-01",
                "dueDate": None,
            },
        ],
    }).encode("utf-8")

    rows = parse_kev_json(payload)

    assert {r.cve for r in rows} == {"CVE-2024-1234", "CVE-2023-9999"}
    by_cve = {r.cve: r for r in rows}
    assert by_cve["CVE-2024-1234"].added is not None
    assert by_cve["CVE-2024-1234"].added.isoformat() == "2024-03-04"
    assert by_cve["CVE-2023-9999"].due is None


def test_parse_kev_json_returns_empty_on_garbage():
    assert parse_kev_json(b"not json") == []
    assert parse_kev_json(b'{"vulnerabilities": "wrong-shape"}') == []
    assert parse_kev_json(b'{"vulnerabilities": [{"cveID": "not-a-cve"}]}') == []


# -- enrichment ---------------------------------------------------------------

class _StubRow:
    def __init__(self, cve, epss_score=None, epss_percentile=None, kev=False):
        self.cve = cve
        self.epss_score = epss_score
        self.epss_percentile = epss_percentile
        self.kev = kev


class _StubSession:
    """Stand-in for an SQLAlchemy session. enrich_with_threat_intel ends up
    calling `lookup_many(session, cves)` — we patch that function directly in
    the test below, so the session itself only needs to exist."""


def test_enrich_attaches_scores_for_findings_with_cves(monkeypatch):
    findings = [
        _mk_finding("CVE-2024-1234"),
        _mk_finding("cve-2023-9999"),  # case is normalized at lookup
        _mk_finding(None),  # findings without a CVE pass through untouched
    ]
    rows = {
        "CVE-2024-1234": _StubRow("CVE-2024-1234", 0.91, 0.99, kev=True),
        "CVE-2023-9999": _StubRow("CVE-2023-9999", 0.02, 0.40, kev=False),
    }
    monkeypatch.setattr("worker.normalize.threat_intel.lookup_many",
                        lambda session, cves: rows)

    enriched = enrich_with_threat_intel(findings, _StubSession())

    assert enriched[0].epss_score == pytest.approx(0.91)
    assert enriched[0].kev is True
    assert enriched[1].epss_score == pytest.approx(0.02)
    assert enriched[1].kev is False
    assert enriched[2].epss_score is None
    assert enriched[2].kev is False


def test_enrich_no_op_when_no_cves(monkeypatch):
    # If no finding has a CVE we must not touch the DB at all.
    called = {"n": 0}

    def fail_if_called(*a, **kw):
        called["n"] += 1
        return {}

    monkeypatch.setattr("worker.normalize.threat_intel.lookup_many", fail_if_called)
    out = enrich_with_threat_intel([_mk_finding(None), _mk_finding(None)], _StubSession())

    assert called["n"] == 0
    assert all(f.epss_score is None and f.kev is False for f in out)


def test_enrich_swallows_lookup_errors(monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("db down")

    monkeypatch.setattr("worker.normalize.threat_intel.lookup_many", boom)
    f = _mk_finding("CVE-2024-1234")
    out = enrich_with_threat_intel([f], _StubSession())

    # Findings flow through with default values — enrichment is best-effort.
    assert out[0].epss_score is None
    assert out[0].kev is False
