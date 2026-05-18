"""Tests for chat suggested questions."""
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
    cwe: str | None = None
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


def _r(**over) -> Row:
    base = dict(id=uuid4(), audit_id=uuid4(), dedupe_key=f"dk-{uuid4().hex[:6]}",
                title="A finding", severity="High")
    base.update(over)
    return Row(**base)


def _audit(priority_list=None):
    profile = {"priority_list": priority_list} if priority_list is not None else None
    return types.SimpleNamespace(id=uuid4(), profile=profile)


def test_no_findings_returns_empty():
    from app.services.suggested_questions import suggested_questions
    assert suggested_questions(_audit(), []) == []


def test_returns_at_most_three():
    from app.services.suggested_questions import suggested_questions
    rows = [_r(title=f"Issue {i}", raw_reference={"rule_id": f"r{i}"}, cwe=f"CWE-{i}")
            for i in range(10)]
    out = suggested_questions(_audit(), rows)
    assert len(out) == 3
    assert all("label" in q and "prompt" in q for q in out)


def test_kev_cluster_gets_kev_question():
    from app.services.suggested_questions import suggested_questions
    out = suggested_questions(_audit(), [_r(kev=True, severity="Critical")])
    assert "kev" in out[0]["label"].lower()


def test_secret_cluster_gets_rotation_question():
    from app.services.suggested_questions import suggested_questions
    rows = [_r(category="Secret Exposure", cwe="CWE-798", raw_reference={"rule_id": "secret"})]
    out = suggested_questions(_audit(), rows)
    assert any("rotation" in q["prompt"].lower() for q in out)


def test_high_instance_cluster_gets_shared_root_question():
    from app.services.suggested_questions import suggested_questions
    rows = [_r(title="SQLi pattern", raw_reference={"rule_id": "sqli"}) for _ in range(7)]
    out = suggested_questions(_audit(), rows)
    assert any("shared" in q["prompt"].lower() or "helper" in q["prompt"].lower() for q in out)


def test_all_unreachable_cluster_excluded():
    """A cluster every-instance-unreachable shouldn't drive a starter question
    — by definition it's low-priority noise. The audit should fall back to
    generic questions."""
    from app.services.suggested_questions import suggested_questions
    rows = [_r(reachable=False, category="Vulnerable Dependency",
               raw_reference={"pkg": "ghost"}, cve="CVE-x")]
    out = suggested_questions(_audit(), rows)
    # When all clusters are unreachable, we get nothing back (cleaner than
    # surfacing low-signal prompts).
    assert out == []


def test_priority_list_drives_ordering():
    """When the audit has a priority_list, suggested questions must follow it,
    not the default severity sort."""
    from app.services.suggested_questions import suggested_questions
    from app.services.clusters import cluster_findings

    crit = _r(severity="Critical", raw_reference={"rule_id": "crit-rule"}, cwe="CWE-89")
    high = _r(severity="High", raw_reference={"rule_id": "high-rule"}, cwe="CWE-79")
    [crit_cluster] = [c for c in cluster_findings([crit]) if c.title == crit.title]
    [high_cluster] = [c for c in cluster_findings([high]) if c.title == high.title]

    # Priority list intentionally inverts severity order.
    audit = _audit(priority_list=[
        {"cluster_key": high_cluster.key, "reason": "go here first"},
        {"cluster_key": crit_cluster.key, "reason": "then this"},
    ])
    out = suggested_questions(audit, [crit, high])
    # First suggestion should be the High one, per priority_list, not Critical.
    assert "high" in out[0]["prompt"].lower() or high.title in out[0]["prompt"]
