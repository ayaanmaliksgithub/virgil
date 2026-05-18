"""Enrich findings with OWASP Top-10 (2021) categories and validate CWE/CVE strings."""
from __future__ import annotations

import re

OWASP_TOP_10_2021 = {
    "A01": "A01:2021 - Broken Access Control",
    "A02": "A02:2021 - Cryptographic Failures",
    "A03": "A03:2021 - Injection",
    "A04": "A04:2021 - Insecure Design",
    "A05": "A05:2021 - Security Misconfiguration",
    "A06": "A06:2021 - Vulnerable and Outdated Components",
    "A07": "A07:2021 - Identification and Authentication Failures",
    "A08": "A08:2021 - Software and Data Integrity Failures",
    "A09": "A09:2021 - Security Logging and Monitoring Failures",
    "A10": "A10:2021 - Server-Side Request Forgery",
}

# Coarse category -> OWASP mapping for findings the scanners did not tag.
CATEGORY_TO_OWASP = {
    "Secret Exposure": OWASP_TOP_10_2021["A07"],
    "Vulnerable Dependency": OWASP_TOP_10_2021["A06"],
    "Infrastructure / IaC Misconfiguration": OWASP_TOP_10_2021["A05"],
    "Injection": OWASP_TOP_10_2021["A03"],
    "Cross-Site Scripting": OWASP_TOP_10_2021["A03"],
    "Server-Side Request Forgery": OWASP_TOP_10_2021["A10"],
    "Path Traversal": OWASP_TOP_10_2021["A01"],
    "Insecure Deserialization": OWASP_TOP_10_2021["A08"],
    "Cryptography": OWASP_TOP_10_2021["A02"],
    "CSRF": OWASP_TOP_10_2021["A01"],
    "Authentication / Session": OWASP_TOP_10_2021["A07"],
    "CORS Misconfiguration": OWASP_TOP_10_2021["A05"],
    "Open Redirect": OWASP_TOP_10_2021["A01"],
}

CWE_RE = re.compile(r"^CWE-\d+$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def normalize_owasp(raw: str | None, category: str) -> str | None:
    if raw:
        # Accept "A01" / "A01:2021 - ..." / lowercase
        m = re.match(r"\s*(A\d{2})", raw, re.IGNORECASE)
        if m:
            key = m.group(1).upper()
            if key in OWASP_TOP_10_2021:
                return OWASP_TOP_10_2021[key]
        return raw  # pass through if non-OWASP framework
    return CATEGORY_TO_OWASP.get(category)


def normalize_cwe(raw: str | None) -> str | None:
    if not raw:
        return None
    s = str(raw).strip().upper()
    if CWE_RE.match(s):
        return s
    m = re.search(r"CWE-(\d+)", s)
    return f"CWE-{m.group(1)}" if m else None


def normalize_cve(raw: str | None) -> str | None:
    if not raw:
        return None
    s = str(raw).strip().upper()
    return s if CVE_RE.match(s) else None
