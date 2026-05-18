"""Suggested follow-up questions for ask-the-auditor chat.

Seeds the chat input with 3 concrete starter questions derived from the
audit's top priority clusters (or, when no priority list exists,
from the highest-severity findings). Deterministic — no LLM call —
so it's fast, free, and stays safe by construction.

Why this matters: an empty chat box is a "what do I even ask?" tax on
the user. With three concrete prompts pre-populated, the chat
becomes a one-click triage assistant.
"""
from __future__ import annotations

from typing import Iterable

from app.db.models import Audit, FindingRow
from app.services.clusters import Cluster, cluster_findings


def suggested_questions(audit: Audit, findings: list[FindingRow]) -> list[dict]:
    """Return up to 3 questions: {label, prompt}.

    `label` is a short button label; `prompt` is what gets sent to the chat
    endpoint. Together they let the UI render `[ $ ask: why is X a problem? ]`
    style buttons that pre-fill the textarea on click.
    """
    if not findings:
        return []

    clusters = cluster_findings(findings)
    clusters = [c for c in clusters if not c.all_unreachable]
    if not clusters:
        return []

    priority_list = []
    if isinstance(audit.profile, dict):
        priority_list = audit.profile.get("priority_list") or []

    # Prefer LLM-ranked priority order; fall back to severity sort.
    ordered: list[Cluster]
    if priority_list:
        by_key = {c.key: c for c in clusters}
        ordered = [by_key[p["cluster_key"]] for p in priority_list if p.get("cluster_key") in by_key]
        # Pad with leftover clusters if priority_list is short.
        ordered += [c for c in clusters if c not in ordered]
    else:
        ordered = clusters

    out: list[dict] = []
    seen_prompts: set[str] = set()

    for c in ordered:
        for q in _questions_for_cluster(c):
            if q["prompt"] not in seen_prompts:
                out.append(q)
                seen_prompts.add(q["prompt"])
                break  # one question per cluster — we want variety
        if len(out) >= 3:
            break

    # If we still have <3 (small audit) add a couple of generic ones grounded
    # in real audit data.
    if len(out) < 3:
        out.extend(_generic_questions(clusters, exclude=seen_prompts))
    return out[:3]


def _questions_for_cluster(c: Cluster) -> list[dict]:
    """Generate candidate questions for one cluster, in order of preference."""
    candidates: list[dict] = []
    title_short = c.title[:80]

    if c.kev:
        candidates.append({
            "label": "kev in this code?",
            "prompt": f"This audit flagged a KEV-listed issue: \"{title_short}\". Walk me through whether this codebase is actually exposed to it and what surface area to look at first.",
        })

    if c.category == "Vulnerable Dependency" and c.any_unreachable is False and c.cves:
        cve_str = ", ".join(c.cves[:3])
        candidates.append({
            "label": "is this dep used?",
            "prompt": f"How is the package referenced by \"{title_short}\" (CVEs: {cve_str}) used in this codebase, and which call sites are at risk?",
        })

    if c.instances >= 5:
        candidates.append({
            "label": f"{c.instances} callsites — shared root?",
            "prompt": f"There are {c.instances} instances of \"{title_short}\" across {len(c.files)} files. Is there a shared helper or upstream module I should fix once instead of every callsite?",
        })

    if c.category == "Secret Exposure":
        candidates.append({
            "label": "secret rotation scope?",
            "prompt": f"Given the finding \"{title_short}\", what's the rotation scope I need to think about — only this credential, or related services?",
        })

    if c.category == "Injection":
        candidates.append({
            "label": "input flow?",
            "prompt": f"For \"{title_short}\", trace the input flow at the cited line and tell me whether any upstream sanitization already mitigates it.",
        })

    # Generic per-cluster fallback so every cluster has at least one question.
    candidates.append({
        "label": f"why is this {c.severity.lower()}?",
        "prompt": f"Explain why \"{title_short}\" is rated {c.severity} for this codebase specifically, given the code context.",
    })
    return candidates


def _generic_questions(clusters: list[Cluster], exclude: set[str]) -> list[dict]:
    """Audit-wide questions when we couldn't fill 3 from cluster-specific ones."""
    generic = [
        {
            "label": "where to start?",
            "prompt": "Given everything in this audit, where should I spend my first hour and why?",
        },
        {
            "label": "what's mostly noise?",
            "prompt": "Which findings in this audit are likely false positives or low-priority given the codebase, and how can you tell?",
        },
        {
            "label": "biggest blind spots?",
            "prompt": "Based on what the scanners found, what gaps in the codebase's defenses worry you most that an automated tool wouldn't catch?",
        },
    ]
    return [q for q in generic if q["prompt"] not in exclude]
