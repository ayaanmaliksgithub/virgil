"""Build executive / technical report payloads from persisted findings.

These are JSON-first; markdown rendering layers on top. No LLM call here —
LLM-generated fields (`business_impact`, `safe_guidance`, etc.) are already
persisted on each finding by the worker.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from app.db.models import Audit, FindingRow

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


def _severity_counts(findings: list[FindingRow]) -> dict[str, int]:
    c = Counter(f.severity for f in findings)
    return {s: c.get(s, 0) for s in SEV_ORDER}


def _category_counts(findings: list[FindingRow]) -> dict[str, int]:
    return dict(Counter(f.category for f in findings).most_common())


def _owasp_counts(findings: list[FindingRow]) -> dict[str, int]:
    return dict(Counter((f.owasp_category or "Unmapped") for f in findings).most_common())


def build_executive(audit: Audit, findings: list[FindingRow]) -> dict[str, Any]:
    sev = _severity_counts(findings)
    top = sorted(findings, key=lambda f: SEV_ORDER.index(f.severity))[:5]
    return {
        "audit_id": str(audit.id),
        "source": {"kind": audit.source_kind, "ref": audit.source_ref, "sha": audit.sha},
        "generated_at": audit.finished_at.isoformat() if audit.finished_at else None,
        "summary": {
            "total_findings": len(findings),
            "severity_breakdown": sev,
            "owasp_breakdown": _owasp_counts(findings),
        },
        "top_findings": [
            {
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "owasp_category": f.owasp_category,
                "business_impact": f.business_impact,
            }
            for f in top
        ],
        "narrative": _highest_value_narrative(audit, findings),
    }


def build_technical(audit: Audit, findings: list[FindingRow]) -> dict[str, Any]:
    return {
        "audit_id": str(audit.id),
        "source": {"kind": audit.source_kind, "ref": audit.source_ref, "sha": audit.sha},
        "generated_at": audit.finished_at.isoformat() if audit.finished_at else None,
        "profile": audit.profile,
        "summary": {
            "total_findings": len(findings),
            "severity_breakdown": _severity_counts(findings),
            "category_breakdown": _category_counts(findings),
            "owasp_breakdown": _owasp_counts(findings),
        },
        "findings": [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity,
                "confidence": f.confidence,
                "category": f.category,
                "owasp_category": f.owasp_category,
                "cwe": f.cwe,
                "cve": f.cve,
                "affected_files": f.affected_files,
                "affected_lines": f.affected_lines,
                "evidence": f.evidence,
                "explanation": f.explanation,
                "exploitability_summary": f.exploitability_summary,
                "business_impact": f.business_impact,
                "safe_guidance": f.safe_guidance,
                "source_tool": f.source_tool,
                "epss_score": f.epss_score,
                "epss_percentile": f.epss_percentile,
                "kev": bool(f.kev),
                "compliance": dict(getattr(f, "compliance", {}) or {}),
                "reachable": getattr(f, "reachable", None),
                "status": f.status,
            }
            for f in sorted(findings, key=lambda f: (SEV_ORDER.index(f.severity), f.category))
        ],
    }


def _highest_value_narrative(audit: Audit, findings: list[FindingRow]) -> str:
    # If the worker stored an LLM-generated narrative on the audit profile,
    # surface it. Otherwise return a deterministic summary so the platform
    # never blocks on missing AI output.
    if isinstance(audit.profile, dict) and audit.profile.get("narrative"):
        return str(audit.profile["narrative"])
    sev = _severity_counts(findings)
    return (
        f"This audit identified {len(findings)} findings — "
        f"{sev['Critical']} Critical, {sev['High']} High, {sev['Medium']} Medium, "
        f"{sev['Low']} Low, {sev['Informational']} Informational. "
        "Refer to the technical report for evidence, affected locations, and high-level "
        "defensive guidance. This report is for risk awareness; it does not include "
        "exploit payloads or step-by-step remediation."
    )


def render_markdown(payload: dict[str, Any], view: str) -> str:
    out: list[str] = []
    title = "Executive Audit Report" if view == "executive" else "Technical Audit Report"
    out.append(f"# {title}\n")
    src = payload.get("source", {})
    out.append(f"- **Source:** `{src.get('kind')}` — {src.get('ref')}")
    if src.get("sha"):
        out.append(f"- **Commit:** `{src['sha']}`")
    out.append(f"- **Audit ID:** `{payload.get('audit_id')}`")
    if payload.get("generated_at"):
        out.append(f"- **Generated:** {payload['generated_at']}")
    out.append("")

    summary = payload.get("summary", {})
    sev = summary.get("severity_breakdown", {})
    out.append("## Severity breakdown\n")
    out.append("| Severity | Count |\n|---|---|")
    for s in SEV_ORDER:
        out.append(f"| {s} | {sev.get(s, 0)} |")
    out.append("")

    if view == "executive":
        out.append("## Narrative\n")
        out.append(payload.get("narrative", ""))
        out.append("\n## Top findings\n")
        for f in payload.get("top_findings", []):
            out.append(f"- **[{f['severity']}] {f['title']}** — {f.get('category')}"
                       + (f" · {f.get('owasp_category')}" if f.get('owasp_category') else ""))
            if f.get("business_impact"):
                out.append(f"  - _Business impact:_ {f['business_impact']}")
        return "\n".join(out) + "\n"

    out.append("## Findings\n")
    for f in payload.get("findings", []):
        out.append(f"### [{f['severity']}] {f['title']}")
        out.append(f"- **Category:** {f['category']}")
        if f.get("owasp_category"):
            out.append(f"- **OWASP:** {f['owasp_category']}")
        if f.get("cwe"):
            out.append(f"- **CWE:** {f['cwe']}")
        if f.get("cve"):
            out.append(f"- **CVE:** {f['cve']}")
        if f.get("kev"):
            out.append("- **CISA KEV:** known exploited in the wild")
        if f.get("epss_score") is not None:
            pct = f.get("epss_percentile")
            pct_str = f" (percentile {pct:.2f})" if isinstance(pct, (int, float)) else ""
            out.append(f"- **EPSS:** {f['epss_score']:.4f}{pct_str}")
        reachable = f.get("reachable")
        if reachable is False:
            out.append("- **Reachability:** unreachable (not imported in source) — severity demoted")
        elif reachable is True:
            out.append("- **Reachability:** reachable (imported in source)")
        compliance = f.get("compliance") or {}
        if compliance:
            controls = ", ".join(
                f"{framework}: {' / '.join(ctrls)}"
                for framework, ctrls in sorted(compliance.items())
                if ctrls
            )
            if controls:
                out.append(f"- **Compliance controls:** {controls}")
        out.append(f"- **Confidence:** {f['confidence']}")
        out.append(f"- **Source:** {', '.join(f['source_tool'])}")
        if f["affected_files"]:
            out.append("- **Affected files:**")
            for af in f["affected_files"]:
                out.append(f"  - `{af}`")
        out.append("")
        if f.get("explanation"):
            out.append(f["explanation"])
            out.append("")
        if f.get("business_impact"):
            out.append(f"**Business impact:** {f['business_impact']}\n")
        if f.get("safe_guidance"):
            out.append(f"**Defensive guidance (high-level):** {f['safe_guidance']}\n")
        if f.get("evidence"):
            out.append("```text")
            out.append(f["evidence"])
            out.append("```\n")
    return "\n".join(out) + "\n"
