"""Tests for SARIF v2.1.0 export (Phase 5 #17).

The full route layer needs FastAPI + the test Postgres; here we pin the
pure builder against in-memory stubs so the SARIF shape regressions are
caught fast.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

pytest.importorskip("pydantic")
pytest.importorskip("sqlalchemy")


def _builder():
    from app.services.sarif import build_sarif
    return build_sarif


@dataclass
class StubAudit:
    id: UUID
    source_kind: str = "url"
    source_ref: str = "https://github.com/example/repo"


@dataclass
class StubFinding:
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
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def _f(**overrides) -> StubFinding:
    base = dict(
        id=uuid4(),
        audit_id=uuid4(),
        dedupe_key="dk-1",
        title="SQL injection in handler",
        severity="High",
        confidence="High confidence",
        category="Injection",
        owasp_category="A03:2021 - Injection",
        cwe="CWE-89",
        affected_files=["src/app.py"],
        affected_lines=[{"file": "src/app.py", "start": 42, "end": 42}],
        explanation="user input flows into raw SQL",
        business_impact="DB read/write under attacker control",
        safe_guidance="parameterize queries; defensive only",
        source_tool=["semgrep"],
    )
    base.update(overrides)
    return StubFinding(**base)


def test_empty_findings_still_emits_one_run_with_metadata():
    build = _builder()
    doc = build(StubAudit(id=uuid4()), [])
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("/sarif-2.1.0.json")
    assert len(doc["runs"]) == 1
    assert doc["runs"][0]["tool"]["driver"]["name"] == "virgil"
    assert doc["runs"][0]["results"] == []


def test_findings_split_into_one_run_per_source_tool():
    build = _builder()
    audit = StubAudit(id=uuid4())
    doc = build(audit, [
        _f(source_tool=["semgrep"]),
        _f(source_tool=["trivy"]),
        _f(source_tool=["semgrep"]),
    ])
    tools = sorted(r["tool"]["driver"]["properties"]["underlying_tool"] for r in doc["runs"])
    assert tools == ["semgrep", "trivy"]
    # semgrep run has 2 results, trivy has 1.
    by_tool = {r["tool"]["driver"]["properties"]["underlying_tool"]: r for r in doc["runs"]}
    assert len(by_tool["semgrep"]["results"]) == 2
    assert len(by_tool["trivy"]["results"]) == 1


def test_result_level_maps_from_severity():
    build = _builder()
    findings = [
        _f(severity="Critical", dedupe_key="c"),
        _f(severity="High", dedupe_key="h"),
        _f(severity="Medium", dedupe_key="m"),
        _f(severity="Low", dedupe_key="l"),
        _f(severity="Informational", dedupe_key="i"),
    ]
    doc = build(StubAudit(id=uuid4()), findings)
    levels = sorted(r["level"] for r in doc["runs"][0]["results"])
    # error appears twice (Critical + High), warning once (Medium),
    # note once (Low), none once (Informational).
    assert levels.count("error") == 2
    assert levels.count("warning") == 1
    assert levels.count("note") == 1
    assert levels.count("none") == 1


def test_rule_has_security_severity_and_cwe_helpuri():
    build = _builder()
    doc = build(StubAudit(id=uuid4()), [_f(cwe="CWE-89")])
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "8.0"  # High → 8.0
    assert rule["helpUri"].endswith("/89.html")
    assert rule["properties"]["cwe"] == ["CWE-89"]


def test_compliance_serialized_as_flat_tags():
    build = _builder()
    doc = build(
        StubAudit(id=uuid4()),
        [_f(compliance={"SOC2": ["CC6.1"], "PCI-DSS": ["6.2.4"]})],
    )
    tags = doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
    assert "SOC2:CC6.1" in tags
    assert "PCI-DSS:6.2.4" in tags


def test_kev_and_epss_propagate_to_result_properties():
    build = _builder()
    doc = build(StubAudit(id=uuid4()), [_f(kev=True, epss_score=0.92, cve="CVE-2024-1")])
    props = doc["runs"][0]["results"][0]["properties"]
    assert props["kev"] is True
    assert props["epss_score"] == 0.92
    assert props["cve"] == "CVE-2024-1"


def test_partial_fingerprints_use_dedupe_key():
    build = _builder()
    doc = build(StubAudit(id=uuid4()), [_f(dedupe_key="stable-key-xyz")])
    assert doc["runs"][0]["results"][0]["partialFingerprints"]["dedupeKey/v1"] == "stable-key-xyz"


def test_locations_fall_back_to_file_only_when_no_lines():
    build = _builder()
    doc = build(
        StubAudit(id=uuid4()),
        [_f(affected_files=["pkg/lock.json"], affected_lines=[])],
    )
    loc = doc["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "pkg/lock.json"
    assert "region" not in loc["physicalLocation"]
