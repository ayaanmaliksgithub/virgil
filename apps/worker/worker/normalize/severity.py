"""Map per-tool severity strings to the unified 5-level scale."""
from __future__ import annotations

from audit_core import Severity

_SEMGREP = {
    "INFO": Severity.INFORMATIONAL,
    "INVENTORY": Severity.INFORMATIONAL,
    "EXPERIMENT": Severity.INFORMATIONAL,
    "LOW": Severity.LOW,
    "WARNING": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "ERROR": Severity.HIGH,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}

_TRIVY = {
    "UNKNOWN": Severity.INFORMATIONAL,
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}

_GITLEAKS = {
    "LOW": Severity.MEDIUM,
    "MEDIUM": Severity.HIGH,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}

_CODEQL = {
    "INFORMATIONAL": Severity.INFORMATIONAL,
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
    "NOTE": Severity.LOW,
    "WARNING": Severity.MEDIUM,
    "ERROR": Severity.HIGH,
}


def map_severity(tool: str, raw: str | None) -> Severity:
    if not raw:
        return Severity.MEDIUM
    key = raw.strip().upper()
    table = {
        "semgrep": _SEMGREP,
        "trivy": _TRIVY,
        "gitleaks": _GITLEAKS,
        "codeql": _CODEQL,
    }.get(tool.lower(), {})
    return table.get(key, Severity.MEDIUM)
