"""SARIF v2.1.0 export (Phase 5 #17).

A single transform from `FindingRow` → SARIF so audits can be ingested
by GitHub Code Scanning, VS Code's SARIF viewer, DefectDojo, and other
AppSec tools that speak the format.

We emit one `run` per distinct `source_tool` — that's how SARIF expects
multi-tool aggregation to be modeled, and it lets the consumer toggle
tools independently. The Finding's normalized rule (id + title + help)
is what ends up under each tool's `tool.driver.rules`.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/sarif-v2.1.0-cs01.html
"""
from __future__ import annotations

from typing import Iterable

from app.db.models import Audit, FindingRow

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
DRIVER_NAME = "virgil"

# SARIF "level" enum is {none, note, warning, error}. The audit platform's
# 5-level scale collapses cleanly: Critical/High → error, Medium → warning,
# Low → note, Informational → none.
_LEVEL = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
    "Informational": "none",
}


def build_sarif(audit: Audit, findings: Iterable[FindingRow]) -> dict:
    """Return a SARIF v2.1.0 document for an audit + its findings."""
    findings_list = list(findings)
    runs_by_tool: dict[str, _RunBuilder] = {}
    for f in findings_list:
        for tool in (f.source_tool or ["virgil"]):
            runs_by_tool.setdefault(tool, _RunBuilder(tool)).add(f)
    runs = [b.build(audit) for b in runs_by_tool.values()]
    if not runs:
        # Always emit one empty run so consumers see a valid document with the
        # audit's metadata even when no findings were produced.
        runs = [_RunBuilder("virgil").build(audit)]
    return {"$schema": SCHEMA, "version": SARIF_VERSION, "runs": runs}


class _RunBuilder:
    def __init__(self, tool_name: str) -> None:
        self.tool_name = tool_name
        self._rules: dict[str, dict] = {}
        self._results: list[dict] = []

    def add(self, f: FindingRow) -> None:
        rule_id = _rule_id(f)
        self._rules.setdefault(rule_id, {
            "id": rule_id,
            "name": (f.category or "Finding").replace(" ", ""),
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": (f.explanation or f.title)[:1000]},
            "help": {"text": (f.safe_guidance or "See finding for high-level guidance.")[:2000]},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[1]}.html" if f.cwe and f.cwe.startswith("CWE-") else None,
            "properties": _rule_properties(f),
        })
        # SARIF rejects keys with `None` values for some consumers; strip.
        self._rules[rule_id] = {k: v for k, v in self._rules[rule_id].items() if v is not None}
        self._results.append(_result_for(f, rule_id))

    def build(self, audit: Audit) -> dict:
        return {
            "tool": {
                "driver": {
                    "name": DRIVER_NAME,
                    "informationUri": "https://virgilhq.app",
                    "rules": list(self._rules.values()),
                    "properties": {"underlying_tool": self.tool_name},
                }
            },
            "automationDetails": {"id": f"{audit.id}/{self.tool_name}"},
            "results": self._results,
        }


def _rule_id(f: FindingRow) -> str:
    """A stable rule id per (category, cwe). Falls back to dedupe_key prefix."""
    if f.cwe:
        return f"{f.category.replace(' ', '_')}/{f.cwe}".lower()
    return f"{f.category.replace(' ', '_')}/finding".lower()


def _rule_properties(f: FindingRow) -> dict:
    props: dict = {"security-severity": _security_severity(f.severity)}
    if f.cwe:
        props["cwe"] = [f.cwe]
    if f.owasp_category:
        props["owasp"] = [f.owasp_category]
    compliance = dict(getattr(f, "compliance", {}) or {})
    if compliance:
        # Flat tag list since SARIF properties are loosely typed.
        tags = [f"{k}:{c}" for k, ctrls in compliance.items() for c in ctrls]
        props["tags"] = tags
    return props


def _security_severity(severity: str) -> str:
    """GitHub Code Scanning expects a 0.0–10.0 string in this property."""
    return {
        "Critical": "9.5",
        "High": "8.0",
        "Medium": "5.5",
        "Low": "3.0",
        "Informational": "0.5",
    }.get(severity, "0.0")


def _result_for(f: FindingRow, rule_id: str) -> dict:
    locations = []
    for al in (f.affected_lines or []):
        loc = {
            "physicalLocation": {
                "artifactLocation": {"uri": al.get("file") if isinstance(al, dict) else getattr(al, "file", "")},
                "region": {"startLine": (al.get("start") if isinstance(al, dict) else getattr(al, "start", 1)) or 1},
            }
        }
        end = al.get("end") if isinstance(al, dict) else getattr(al, "end", None)
        if end:
            loc["physicalLocation"]["region"]["endLine"] = end
        locations.append(loc)
    if not locations and f.affected_files:
        locations = [{"physicalLocation": {"artifactLocation": {"uri": p}}} for p in f.affected_files]

    result = {
        "ruleId": rule_id,
        "level": _LEVEL.get(f.severity, "warning"),
        "message": {"text": (f.business_impact or f.explanation or f.title)[:2000]},
        "locations": locations,
        "partialFingerprints": {"dedupeKey/v1": f.dedupe_key},
        "properties": {"severity": f.severity, "confidence": f.confidence},
    }
    if f.cve:
        result["properties"]["cve"] = f.cve
    if getattr(f, "kev", False):
        result["properties"]["kev"] = True
    if getattr(f, "epss_score", None) is not None:
        result["properties"]["epss_score"] = f.epss_score
    return result
