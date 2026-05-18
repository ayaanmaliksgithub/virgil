"""Tests for the suppression-triggered priority refresh.

We test the service function with a stubbed db/audit pair — the API
integration path (route → service) is exercised by `tests/api/...` when
TEST_DATABASE_URL is set.
"""
from __future__ import annotations

import os
import types
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

pytest.importorskip("pydantic")
pytest.importorskip("sqlalchemy")


@dataclass
class Row:
    id: UUID
    audit_id: UUID
    dedupe_key: str
    title: str
    severity: str
    confidence: str = "High confidence"
    category: str = "Injection"
    owasp_category: str | None = None
    cwe: str | None = "CWE-89"
    cve: str | None = None
    affected_files: list = field(default_factory=lambda: ["src/app.py"])
    affected_lines: list = field(default_factory=list)
    evidence: str = ""
    explanation: str = ""
    exploitability_summary: str | None = None
    business_impact: str | None = None
    safe_guidance: str | None = None
    source_tool: list = field(default_factory=lambda: ["semgrep"])
    raw_reference: dict = field(default_factory=lambda: {"rule_id": "r1"})
    epss_score: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    compliance: dict = field(default_factory=dict)
    reachable: bool | None = None
    status: str = "open"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class StubScalar:
    def __init__(self, rows): self._rows = rows
    def scalars(self): return self
    def all(self): return self._rows


class StubDB:
    """Just enough Session shape for refresh_priority_list."""
    def __init__(self, rows, suppressed_keys):
        self.rows = rows
        self.suppressed = suppressed_keys
        self.commits = 0

    def execute(self, stmt):
        # Tests don't differentiate the query — return all rows.
        # `suppression_keys` is monkeypatched separately to avoid coupling.
        return StubScalar(self.rows)

    def commit(self):
        self.commits += 1


def test_refresh_writes_priority_list_for_remaining_clusters(monkeypatch):
    from app.services import triage_refresh

    a_high = Row(id=uuid4(), audit_id=uuid4(), dedupe_key="A",
                 title="SQLi pattern", severity="High",
                 raw_reference={"rule_id": "sqli"}, cwe="CWE-89")
    b_low = Row(id=uuid4(), audit_id=uuid4(), dedupe_key="B",
                title="Info leak", severity="Low",
                raw_reference={"rule_id": "info"}, cwe="CWE-200")

    db = StubDB([a_high, b_low], suppressed_keys=set())
    audit = types.SimpleNamespace(
        id=uuid4(),
        source_ref="https://github.com/example/repo",
        profile=None,
    )

    monkeypatch.setattr(triage_refresh, "suppression_keys", lambda *a, **k: set())
    triage_refresh.refresh_priority_list(db, audit)

    assert audit.profile is not None
    pl = audit.profile["priority_list"]
    # High before Low; both still present.
    assert pl[0]["cluster_key"] != pl[1]["cluster_key"]
    assert any("High" in p["reason"] or "high" in p["reason"] for p in pl)


def test_refresh_drops_fully_suppressed_clusters(monkeypatch):
    from app.services import triage_refresh

    a = Row(id=uuid4(), audit_id=uuid4(), dedupe_key="A",
            title="Suppressed", severity="Critical",
            raw_reference={"rule_id": "x"}, cwe="CWE-1")
    b = Row(id=uuid4(), audit_id=uuid4(), dedupe_key="B",
            title="Still active", severity="Low",
            raw_reference={"rule_id": "y"}, cwe="CWE-2")
    db = StubDB([a, b], suppressed_keys={"A"})
    audit = types.SimpleNamespace(
        id=uuid4(),
        source_ref="repo",
        profile={"priority_list": [{"cluster_key": "old", "reason": "stale"}]},
    )

    monkeypatch.setattr(triage_refresh, "suppression_keys", lambda *a, **k: {"A"})
    triage_refresh.refresh_priority_list(db, audit)

    pl = audit.profile["priority_list"]
    # Only one cluster left (b's). The Critical (suppressed) is gone, and
    # the stale entry was replaced.
    assert len(pl) == 1


def test_refresh_clears_priority_when_everything_suppressed(monkeypatch):
    from app.services import triage_refresh

    a = Row(id=uuid4(), audit_id=uuid4(), dedupe_key="A",
            title="x", severity="Low",
            raw_reference={"rule_id": "z"})
    db = StubDB([a], suppressed_keys={"A"})
    audit = types.SimpleNamespace(
        id=uuid4(), source_ref="repo",
        profile={"priority_list": [{"cluster_key": "old", "reason": "stale"}]},
    )
    monkeypatch.setattr(triage_refresh, "suppression_keys", lambda *a, **k: {"A"})
    triage_refresh.refresh_priority_list(db, audit)

    assert "priority_list" not in (audit.profile or {})


def test_refresh_with_no_findings_clears_priority_list(monkeypatch):
    from app.services import triage_refresh

    db = StubDB([], suppressed_keys=set())
    audit = types.SimpleNamespace(
        id=uuid4(), source_ref="repo",
        profile={"priority_list": [{"cluster_key": "k", "reason": "x"}], "narrative": "keep me"},
    )
    monkeypatch.setattr(triage_refresh, "suppression_keys", lambda *a, **k: set())
    triage_refresh.refresh_priority_list(db, audit)

    # priority_list removed, narrative preserved.
    assert "priority_list" not in audit.profile
    assert audit.profile.get("narrative") == "keep me"
