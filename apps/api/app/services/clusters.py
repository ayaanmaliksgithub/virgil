"""Findings clustering.

A 200-row table teaches users that all findings are equal weight and
that triaging means scrolling. Most of the time those 200 rows are 8
real problems × ~25 callsites each — and the right unit of attention
is the cluster, not the row.

This module groups findings by a stable cluster_key derived from
`(category, cwe, rule_signature)`. The rule signature is whatever
scanner-specific identifier survives normalization — Semgrep's
`check_id`, Trivy's `pkg`/`id`, Gitleaks' `rule_id`. We deliberately
do NOT cluster by file+line (that's `dedupe_key`'s job), nor by
free-text title (too unstable).

A cluster's representative finding is the highest-severity, most-
confident instance. That's what we link to from the cluster view, and
it's what feeds into the LLM priority list (next item).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from app.db.models import FindingRow

# Severity ordering shared with the rest of the codebase. Higher index = lower.
_SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
_CONF_ORDER = ["High confidence", "Medium confidence", "Low confidence",
               "Requires manual verification"]


@dataclass
class Cluster:
    key: str
    category: str
    cwe: str | None
    rule_signature: str
    title: str                     # representative finding's title
    severity: str                  # highest seen
    confidence: str                # best seen
    instances: int
    files: list[str]               # de-duped, sorted, first 12
    cves: list[str]                # de-duped, sorted, first 8
    kev: bool
    any_unreachable: bool
    all_unreachable: bool
    representative_id: str         # finding to link to from the cluster row
    finding_ids: list[str] = field(default_factory=list)


def _rule_signature(f: FindingRow) -> str:
    """The most-stable scanner id we can extract.

    For dep findings (Trivy) we want to cluster by package, NOT by CVE —
    a single vulnerable package is one fix even when it lists five CVEs.
    For misconfigs we cluster by rule id. For everything else we fall
    back to the normalized rule_id stored in raw_reference, or the title
    (last resort)."""
    raw = f.raw_reference or {}
    if isinstance(raw, dict):
        if raw.get("pkg"):
            return f"pkg:{str(raw['pkg']).lower()}"
        if raw.get("rule_id"):
            return f"rule:{str(raw['rule_id'])}"
        if raw.get("check_id"):
            return f"rule:{str(raw['check_id'])}"
        if raw.get("id"):
            return f"rule:{str(raw['id'])}"
    # Last resort — hash the title so we still cluster identical findings
    # whose adapter didn't surface a stable rule id.
    return "title:" + hashlib.sha1(f.title.encode("utf-8")).hexdigest()[:12]


def _cluster_key(f: FindingRow) -> str:
    sig = _rule_signature(f)
    parts = [
        f.category or "uncategorized",
        f.cwe or "no-cwe",
        sig,
    ]
    blob = "|".join(parts)
    return hashlib.sha1(blob.encode("utf-8")).hexdigest()[:16]


def _sev_idx(sev: str) -> int:
    try:
        return _SEV_ORDER.index(sev)
    except ValueError:
        return len(_SEV_ORDER)


def _conf_idx(conf: str) -> int:
    try:
        return _CONF_ORDER.index(conf)
    except ValueError:
        return len(_CONF_ORDER)


def cluster_findings(findings: Sequence[FindingRow]) -> list[Cluster]:
    """Group findings into clusters. Returns clusters ordered by:
    severity ASC (index) → instance count DESC."""
    groups: dict[str, list[FindingRow]] = {}
    for f in findings:
        groups.setdefault(_cluster_key(f), []).append(f)

    clusters: list[Cluster] = []
    for key, rows in groups.items():
        rep = min(rows, key=lambda r: (_sev_idx(r.severity), _conf_idx(r.confidence)))
        files: list[str] = []
        seen_files: set[str] = set()
        for r in rows:
            for af in (r.affected_files or []):
                if af not in seen_files:
                    seen_files.add(af)
                    files.append(af)
        cves = sorted({r.cve for r in rows if r.cve})
        any_unr = any(getattr(r, "reachable", None) is False for r in rows)
        all_unr = bool(rows) and all(getattr(r, "reachable", None) is False for r in rows)
        clusters.append(Cluster(
            key=key,
            category=rep.category,
            cwe=rep.cwe,
            rule_signature=_rule_signature(rep),
            title=rep.title,
            severity=rep.severity,
            confidence=rep.confidence,
            instances=len(rows),
            files=sorted(files)[:12],
            cves=cves[:8],
            kev=any(getattr(r, "kev", False) for r in rows),
            any_unreachable=any_unr,
            all_unreachable=all_unr,
            representative_id=str(rep.id),
            finding_ids=[str(r.id) for r in rows],
        ))

    clusters.sort(key=lambda c: (_sev_idx(c.severity), -c.instances))
    return clusters


def serialize_cluster(c: Cluster) -> dict:
    return {
        "key": c.key,
        "category": c.category,
        "cwe": c.cwe,
        "rule_signature": c.rule_signature,
        "title": c.title,
        "severity": c.severity,
        "confidence": c.confidence,
        "instances": c.instances,
        "files": c.files,
        "cves": c.cves,
        "kev": c.kev,
        "any_unreachable": c.any_unreachable,
        "all_unreachable": c.all_unreachable,
        "representative_id": c.representative_id,
        "finding_ids": c.finding_ids,
    }
