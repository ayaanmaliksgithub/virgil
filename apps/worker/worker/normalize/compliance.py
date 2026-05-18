"""Static compliance-control mapping (Phase 4 §17 #7).

Maps a finding's `(category, cwe)` to control IDs across SOC2, PCI-DSS,
HIPAA Security Rule, and ISO/IEC 27001:2022 Annex A. The mapping is
deliberately coarse — one finding rarely violates a single control in
isolation, and overstating the link reduces the report's credibility
with an auditor. Where a category has obvious analogues across
frameworks (e.g. secret exposure → confidentiality/encryption controls)
we map them; where it doesn't, we leave the framework out for that
category.

This is a maintenance file. Treat each row as a small assertion that
can be challenged independently — extend when a real audit surfaces a
gap, don't synthesize broad mappings ahead of demand.
"""
from __future__ import annotations

from typing import Iterable

from audit_core import Finding

# Category-level mappings. CWE-level overrides layer on top of these so
# specific CWEs can add framework-specific control IDs that a coarse
# category match wouldn't catch.
_CATEGORY_MAP: dict[str, dict[str, list[str]]] = {
    "Secret Exposure": {
        "SOC2": ["CC6.1", "CC6.7"],
        "PCI-DSS": ["3.4", "8.2.1"],
        "HIPAA": ["164.312(a)(2)(iv)", "164.312(e)(2)(ii)"],
        "ISO27001": ["A.5.17", "A.8.24"],
    },
    "Vulnerable Dependency": {
        "SOC2": ["CC7.1"],
        "PCI-DSS": ["6.3.3", "6.4.1"],
        "ISO27001": ["A.8.8", "A.8.28"],
    },
    "Injection": {
        "SOC2": ["CC6.6", "CC7.2"],
        "PCI-DSS": ["6.2.4"],
        "ISO27001": ["A.8.28", "A.8.29"],
    },
    "Authentication": {
        "SOC2": ["CC6.1", "CC6.2"],
        "PCI-DSS": ["8.2", "8.3"],
        "HIPAA": ["164.312(d)"],
        "ISO27001": ["A.5.16", "A.8.5"],
    },
    "Authorization": {
        "SOC2": ["CC6.3"],
        "PCI-DSS": ["7.1", "7.2"],
        "HIPAA": ["164.312(a)(1)"],
        "ISO27001": ["A.5.15", "A.8.3"],
    },
    "Cryptography": {
        "SOC2": ["CC6.1"],
        "PCI-DSS": ["3.5", "4.2"],
        "HIPAA": ["164.312(a)(2)(iv)", "164.312(e)(1)"],
        "ISO27001": ["A.8.24"],
    },
    "Configuration": {
        "SOC2": ["CC7.1"],
        "PCI-DSS": ["2.2"],
        "ISO27001": ["A.8.9"],
    },
    "License Risk": {
        # Not a security control issue per se, but procurement / supply-chain
        # programs care. Mapping intentionally narrow.
        "SOC2": ["CC9.2"],
        "ISO27001": ["A.5.31"],
    },
    "Logging": {
        "SOC2": ["CC7.2", "CC7.3"],
        "PCI-DSS": ["10.2"],
        "HIPAA": ["164.312(b)"],
        "ISO27001": ["A.8.15"],
    },
}

# CWE-level overrides. Use when a CWE crosses categories or pulls a
# specific control id we'd miss at category granularity.
_CWE_MAP: dict[str, dict[str, list[str]]] = {
    "CWE-89":  {"PCI-DSS": ["6.2.4"]},           # SQL injection
    "CWE-79":  {"PCI-DSS": ["6.2.4"]},           # XSS
    "CWE-78":  {"PCI-DSS": ["6.2.4"]},           # OS command injection
    "CWE-22":  {"PCI-DSS": ["6.2.4"]},           # Path traversal
    "CWE-798": {"PCI-DSS": ["8.6.2"]},           # Hard-coded credentials
    "CWE-352": {"PCI-DSS": ["6.2.4"]},           # CSRF
    "CWE-918": {"PCI-DSS": ["6.2.4"]},           # SSRF
    "CWE-502": {"PCI-DSS": ["6.2.4"]},           # Deserialization
    "CWE-200": {"HIPAA": ["164.312(c)(1)"]},     # Information exposure
    "CWE-311": {"PCI-DSS": ["3.5", "4.2"]},      # Missing encryption
    "CWE-327": {"PCI-DSS": ["3.5", "4.2"]},      # Broken crypto
    "CWE-732": {"ISO27001": ["A.8.3"]},          # Incorrect permission
}


def _merge(target: dict[str, list[str]], extra: dict[str, list[str]]) -> None:
    """In-place union per framework, preserving first-seen order."""
    for framework, controls in extra.items():
        bucket = target.setdefault(framework, [])
        for c in controls:
            if c not in bucket:
                bucket.append(c)


def map_finding(category: str | None, cwe: str | None) -> dict[str, list[str]]:
    """Return the merged control map for a (category, cwe) pair."""
    out: dict[str, list[str]] = {}
    if category and category in _CATEGORY_MAP:
        _merge(out, _CATEGORY_MAP[category])
    if cwe and cwe in _CWE_MAP:
        _merge(out, _CWE_MAP[cwe])
    return out


def enrich_with_compliance(findings: Iterable[Finding]) -> list[Finding]:
    """Annotate findings with their compliance control mapping.

    Mutates by creating shallow copies (Pydantic `model_copy`) so callers
    holding references to the input list don't see surprise mutations.
    """
    out: list[Finding] = []
    for f in findings:
        mapped = map_finding(f.category, f.cwe)
        if mapped:
            out.append(f.model_copy(update={"compliance": mapped}))
        else:
            out.append(f)
    return out
