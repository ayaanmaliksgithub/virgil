"""Tests for compliance control mapping (Phase 4 §17 #7).

The mapping table is intentionally small — these tests pin the contract
(merge category + CWE, no duplicate controls, default empty) rather than
the full coverage matrix. When extending the table, add a row here for any
non-obvious mapping so reviewers can challenge it.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic")

from audit_core import AffectedLine, Confidence, Finding, Severity, Status
from worker.normalize.compliance import enrich_with_compliance, map_finding


def _f(category: str, cwe: str | None = None) -> Finding:
    return Finding(
        dedupe_key=f"{category}:{cwe or 'none'}",
        title=f"{category} finding",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=category,
        cwe=cwe,
        affected_files=["x.py"],
        affected_lines=[AffectedLine(file="x.py", start=1)],
        evidence="x",
        explanation="y",
        source_tool=["semgrep"],
        status=Status.OPEN,
    )


def test_category_lookup_returns_known_frameworks():
    mapped = map_finding("Secret Exposure", None)
    assert "SOC2" in mapped
    assert "PCI-DSS" in mapped
    assert "HIPAA" in mapped
    assert "ISO27001" in mapped
    assert "CC6.1" in mapped["SOC2"]


def test_unknown_category_returns_empty():
    assert map_finding("Made Up Category", None) == {}
    assert map_finding(None, None) == {}


def test_cwe_overrides_layer_on_top_of_category():
    base = map_finding("Authentication", None)
    with_cwe = map_finding("Authentication", "CWE-798")  # hard-coded creds
    # CWE adds PCI 8.6.2 that the bare Authentication category lacks.
    assert "8.6.2" in with_cwe["PCI-DSS"]
    assert "8.6.2" not in base.get("PCI-DSS", [])


def test_cwe_only_finding_still_gets_mapping():
    """A finding with no known category but a recognized CWE still maps."""
    mapped = map_finding("Unknown Category", "CWE-89")
    assert mapped == {"PCI-DSS": ["6.2.4"]}


def test_merge_does_not_duplicate_controls():
    """When both category and CWE point at the same control, it appears once."""
    mapped = map_finding("Injection", "CWE-89")
    # PCI-DSS 6.2.4 is in both the category (Injection) and the CWE (CWE-89).
    assert mapped["PCI-DSS"].count("6.2.4") == 1


def test_enrich_attaches_compliance_field():
    findings = [_f("Secret Exposure", "CWE-798"), _f("Made Up Category")]
    out = enrich_with_compliance(findings)
    assert out[0].compliance
    assert out[0].compliance.get("SOC2") == ["CC6.1", "CC6.7"]
    # unmapped categories keep an empty dict, not None.
    assert out[1].compliance == {}


def test_enrich_does_not_mutate_input():
    f = _f("Secret Exposure")
    [_enriched] = enrich_with_compliance([f])
    assert f.compliance == {}  # original untouched
