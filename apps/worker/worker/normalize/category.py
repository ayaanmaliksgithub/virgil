"""Map a raw finding to a stable, human-readable category.

This is intentionally a small table + heuristics. Granular rule_id → category
overrides can be added without disturbing scanner adapters.
"""
from __future__ import annotations

from audit_core import RawFinding


def categorize(rf: RawFinding) -> str:
    rid = rf.rule_id.lower()
    msg = (rf.message or "").lower()

    if rid.startswith("license/"):
        return "License Risk"
    if rid.startswith("secret/") or "secret" in rid or rf.source_tool == "gitleaks":
        return "Secret Exposure"
    if rid.startswith("cve-") or (rf.cve and rf.cve.startswith("CVE-")):
        return "Vulnerable Dependency"
    if any(t in rid for t in ("dockerfile", "kubernetes", "terraform", "iac", "k8s", "helm")):
        return "Infrastructure / IaC Misconfiguration"
    if "sql" in rid or "sql-injection" in rid or "sqli" in msg:
        return "Injection"
    if "xss" in rid or "cross-site-scripting" in rid:
        return "Cross-Site Scripting"
    if "ssrf" in rid:
        return "Server-Side Request Forgery"
    if "path-traversal" in rid or "directory-traversal" in rid:
        return "Path Traversal"
    if "deserial" in rid or "insecure-deserialization" in rid:
        return "Insecure Deserialization"
    if "crypto" in rid or "weak-hash" in rid or "weak-cipher" in rid:
        return "Cryptography"
    if "csrf" in rid:
        return "CSRF"
    if "auth" in rid or "jwt" in rid or "session" in rid:
        return "Authentication / Session"
    if "cors" in rid:
        return "CORS Misconfiguration"
    if "open-redirect" in rid:
        return "Open Redirect"
    if "ssrf" in rid:
        return "SSRF"
    return "Code Quality / Security Smell"
