"""Tests for findings clustering."""
from __future__ import annotations

import os
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
    confidence: str
    category: str
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
    reachable: bool | None = None
    owasp_category: str | None = None
    status: str = "open"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def _r(**over):
    base = dict(
        id=uuid4(),
        audit_id=uuid4(),
        dedupe_key=f"dk-{uuid4().hex[:6]}",
        title="SQL injection",
        severity="High",
        confidence="High confidence",
        category="Injection",
        cwe="CWE-89",
        affected_files=["src/handler.py"],
        raw_reference={"rule_id": "py.sql-injection"},
        source_tool=["semgrep"],
    )
    base.update(over)
    return Row(**base)


def test_same_rule_id_same_cwe_same_category_clusters_together():
    from app.services.clusters import cluster_findings
    rows = [
        _r(affected_files=["a.py"]),
        _r(affected_files=["b.py"]),
        _r(affected_files=["c.py"]),
    ]
    clusters = cluster_findings(rows)
    assert len(clusters) == 1
    assert clusters[0].instances == 3
    assert sorted(clusters[0].files) == ["a.py", "b.py", "c.py"]


def test_different_rule_ids_do_not_cluster():
    from app.services.clusters import cluster_findings
    clusters = cluster_findings([
        _r(raw_reference={"rule_id": "py.sql-injection"}),
        _r(raw_reference={"rule_id": "py.xss"}, title="XSS", cwe="CWE-79"),
    ])
    assert len(clusters) == 2


def test_dep_findings_cluster_by_package_not_cve():
    """One vulnerable package commonly lists multiple CVEs; we want them
    grouped because the fix is "bump the package" once."""
    from app.services.clusters import cluster_findings
    rows = [
        _r(category="Vulnerable Dependency", cwe=None,
           raw_reference={"pkg": "lodash"}, cve="CVE-2024-1", title="lodash CVE-2024-1"),
        _r(category="Vulnerable Dependency", cwe=None,
           raw_reference={"pkg": "lodash"}, cve="CVE-2024-2", title="lodash CVE-2024-2"),
    ]
    clusters = cluster_findings(rows)
    assert len(clusters) == 1
    assert sorted(clusters[0].cves) == ["CVE-2024-1", "CVE-2024-2"]


def test_cluster_severity_is_highest_seen():
    from app.services.clusters import cluster_findings
    rows = [
        _r(severity="Low"),
        _r(severity="Critical"),
        _r(severity="Medium"),
    ]
    cluster = cluster_findings(rows)[0]
    assert cluster.severity == "Critical"
    assert cluster.instances == 3


def test_cluster_marks_kev_if_any_instance_kev():
    from app.services.clusters import cluster_findings
    rows = [_r(kev=False), _r(kev=True), _r(kev=False)]
    cluster = cluster_findings(rows)[0]
    assert cluster.kev is True


def test_cluster_tracks_reachable_partition():
    from app.services.clusters import cluster_findings
    rows = [_r(reachable=False), _r(reachable=False)]
    c = cluster_findings(rows)[0]
    assert c.any_unreachable is True
    assert c.all_unreachable is True

    rows = [_r(reachable=True), _r(reachable=False)]
    c = cluster_findings(rows)[0]
    assert c.any_unreachable is True
    assert c.all_unreachable is False


def test_clusters_sorted_by_severity_then_instances_desc():
    from app.services.clusters import cluster_findings
    rows = [
        _r(severity="Low", raw_reference={"rule_id": "a"}, title="A"),
        _r(severity="Low", raw_reference={"rule_id": "a"}, title="A"),
        _r(severity="High", raw_reference={"rule_id": "b"}, title="B", cwe="CWE-1"),
        _r(severity="High", raw_reference={"rule_id": "c"}, title="C", cwe="CWE-2"),
        _r(severity="High", raw_reference={"rule_id": "c"}, title="C", cwe="CWE-2"),
    ]
    clusters = cluster_findings(rows)
    # All Highs come first; within Highs, the 2-instance cluster wins.
    assert clusters[0].severity == "High"
    assert clusters[0].instances == 2
    assert clusters[1].severity == "High"
    assert clusters[1].instances == 1
    assert clusters[2].severity == "Low"


def test_files_deduped_and_capped():
    from app.services.clusters import cluster_findings
    rows = [
        _r(affected_files=[f"f{i}.py" for i in range(20)])
    ]
    c = cluster_findings(rows)[0]
    assert len(c.files) == 12  # capped


def test_representative_is_highest_severity_finding():
    from app.services.clusters import cluster_findings
    high = _r(severity="High")
    low = _r(severity="Low")
    high.id = UUID("11111111-1111-1111-1111-111111111111")
    low.id = UUID("22222222-2222-2222-2222-222222222222")
    c = cluster_findings([low, high])[0]
    assert c.representative_id == str(high.id)
