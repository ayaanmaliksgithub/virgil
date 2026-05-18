"""Threat-intel enrichment step.

Runs after `normalize_findings` and before report generation: for each finding
with a CVE, attach `epss_score`, `epss_percentile`, and `kev` from the
nightly-refreshed `threat_intel` table. Findings without a CVE are passed
through untouched. Missing rows are not an error — the feeds don't cover every
CVE on day-zero.
"""
from __future__ import annotations

import logging
from typing import Iterable

from audit_core import Finding

from worker.threat_intel import lookup_many

log = logging.getLogger(__name__)


def enrich_with_threat_intel(findings: Iterable[Finding], session) -> list[Finding]:
    findings = list(findings)
    cves = [f.cve for f in findings if f.cve]
    if not cves:
        return findings

    try:
        rows = lookup_many(session, cves)
    except Exception as e:  # nosec — best-effort enrichment, never block the audit
        log.warning("threat_intel lookup failed: %s", type(e).__name__)
        return findings

    for f in findings:
        if not f.cve:
            continue
        row = rows.get(f.cve.strip().upper())
        if row is None:
            continue
        f.epss_score = row.epss_score
        f.epss_percentile = row.epss_percentile
        f.kev = bool(row.kev)
    return findings
