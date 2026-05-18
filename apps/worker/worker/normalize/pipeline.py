"""Normalization pipeline: RawFinding[] -> Finding[].

Stages:
    raw -> severity -> category -> owasp/cwe -> redact -> dedupe
"""
from __future__ import annotations

from collections.abc import Iterable
from uuid import UUID

from audit_core import AffectedLine, Confidence, Finding, RawFinding

from .category import categorize
from .dedupe import dedupe, make_dedupe_key
from .owasp_cwe import normalize_cve, normalize_cwe, normalize_owasp
from .redact import redact
from .severity import map_severity


def _initial_confidence(rf: RawFinding) -> Confidence:
    # Secret detections from gitleaks are usually high-precision; many SAST
    # findings benefit from manual review. This is a coarse default — agreement
    # between tools bumps it during dedupe.
    if rf.source_tool == "gitleaks":
        return Confidence.HIGH
    if rf.source_tool == "trivy" and rf.cve:
        return Confidence.HIGH
    return Confidence.MEDIUM


def to_finding(rf: RawFinding, audit_id: UUID | None) -> Finding:
    category = categorize(rf)
    severity = map_severity(rf.source_tool, rf.raw_severity)
    confidence = _initial_confidence(rf)
    owasp = normalize_owasp(rf.owasp, category)
    cwe = normalize_cwe(rf.cwe)
    cve = normalize_cve(rf.cve)
    evidence = redact(rf.snippet or rf.message)
    explanation = redact(rf.message)

    dedupe_key = make_dedupe_key(rf.rule_id, rf.file, rf.start_line, rf.snippet)
    return Finding(
        audit_id=audit_id,
        dedupe_key=dedupe_key,
        title=rf.title,
        severity=severity,
        confidence=confidence,
        category=category,
        owasp_category=owasp,
        cwe=cwe,
        cve=cve,
        affected_files=[rf.file] if rf.file else [],
        affected_lines=[AffectedLine(file=rf.file, start=rf.start_line, end=rf.end_line)] if rf.file else [],
        evidence=evidence,
        explanation=explanation,
        exploitability_summary=None,  # LLM fills later, schema-bound
        business_impact=None,
        safe_guidance=None,
        source_tool=[rf.source_tool],
        raw_reference={"rule_id": rf.rule_id, **rf.raw},
    )


def normalize_findings(raws: Iterable[RawFinding], audit_id: UUID | None = None) -> list[Finding]:
    findings = [to_finding(rf, audit_id) for rf in raws]
    return dedupe(findings)
