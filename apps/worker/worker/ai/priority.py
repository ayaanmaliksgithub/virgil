"""LLM-ranked priority list (Phase 4 — triage layer).

After enrichment + narrative, ask the LLM to rank-order the top-K
clusters into a "fix this week" list with a short rationale per item.
This is the single biggest UX move toward making the product actually
useful: instead of "here are 200 findings sorted by severity," the
user lands on "here are the 8 you should look at this week, and here's
why each one is on the list."

The rationale stays in the same regime as `safe_guidance` — analytical
reasoning, not operational steps. The safety validator filters output.

Inputs are clusters (already deduped by `cluster_findings`), the repo
profile, and per-cluster signals (severity, instance count, reachable
partition, KEV bit, max EPSS). No raw evidence reaches the LLM.

Output is stashed on `audit.profile["priority_list"]` so the API can
serve it without re-calling the LLM on every page view.
"""
from __future__ import annotations

import json
import logging
from typing import Iterable

from worker.ai.prompts.system import AUDITOR_SYSTEM
from worker.ai.provider import get_provider
from worker.ai.safety import sanitize

log = logging.getLogger(__name__)

PRIORITY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["priorities"],
    "properties": {
        "priorities": {
            "type": "array",
            "maxItems": 12,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["cluster_key", "reason"],
                "properties": {
                    "cluster_key": {"type": "string", "maxLength": 32},
                    "reason": {"type": "string", "maxLength": 280},
                },
            },
        }
    },
}


def _cluster_signal(c) -> dict:
    """Compact signal dict sent to the LLM. Avoids raw evidence on purpose —
    the LLM is ranking, not investigating."""
    return {
        "cluster_key": c.key,
        "title": c.title,
        "severity": c.severity,
        "category": c.category,
        "cwe": c.cwe,
        "instances": c.instances,
        "files_count": len(c.files),
        "cve_count": len(c.cves),
        "kev": c.kev,
        "all_unreachable": c.all_unreachable,
        "any_unreachable": c.any_unreachable,
    }


def build_priority_list(
    clusters: list,
    *,
    profile=None,
    top_k: int = 8,
) -> list[dict]:
    """Return an ordered list of `{cluster_key, reason}` dicts.

    No-op when the LLM provider isn't configured. Returns at most `top_k`
    entries. Guarantees every returned `cluster_key` is present in the
    input clusters (filters out hallucinated keys).
    """
    if not clusters:
        return []

    provider = get_provider()
    if provider.name == "null":
        return _deterministic_fallback(clusters, top_k)

    valid_keys = {c.key for c in clusters}
    candidates = [c for c in clusters if not c.all_unreachable]
    candidates.sort(key=lambda c: _sev_priority(c.severity))
    candidates = candidates[: max(top_k * 3, 12)]  # give the model some headroom

    user = (
        "Repository profile:\n"
        f"{json.dumps(_profile_blob(profile))}\n\n"
        "Finding clusters (candidates for ranking):\n"
        f"{json.dumps([_cluster_signal(c) for c in candidates])}\n\n"
        f"Task: Pick the TOP {top_k} clusters a security engineer should fix "
        "this week, in priority order. For each, write a 1-sentence reason "
        "that explains the ranking — combine severity, KEV status, instance "
        "count, and category to justify priority. \n"
        "RULES:\n"
        "- Do NOT invent cluster_keys; only use keys from the input list.\n"
        "- Do NOT include payloads, exploit code, or step-by-step remediation.\n"
        "- Prefer clusters with kev=true and high instance counts when "
        "severity is tied.\n"
        "- Reason is analytical, not operational. No 'run X then Y'.\n"
    )
    try:
        data = provider.complete_json(
            system=AUDITOR_SYSTEM,
            user=user,
            schema=PRIORITY_SCHEMA,
            max_tokens=1500,
            temperature=0.1,
        )
    except Exception as e:
        log.warning("priority list LLM call failed: %s", type(e).__name__)
        return _deterministic_fallback(clusters, top_k)

    out: list[dict] = []
    seen: set[str] = set()
    for item in (data.get("priorities") or [])[: top_k]:
        key = str(item.get("cluster_key", ""))
        if key not in valid_keys or key in seen:
            continue
        reason = sanitize(item.get("reason", ""), fallback="")
        if not reason:
            continue
        out.append({"cluster_key": key, "reason": reason})
        seen.add(key)
    if not out:
        return _deterministic_fallback(clusters, top_k)
    return out


def _deterministic_fallback(clusters: list, top_k: int) -> list[dict]:
    """When the LLM is off/unavailable, surface the top severity * instances
    clusters with a templated rationale. Keeps the triage view useful in
    OSS-only deployments."""
    ranked = sorted(
        (c for c in clusters if not c.all_unreachable),
        key=lambda c: (_sev_priority(c.severity), -c.instances),
    )[: top_k]
    out: list[dict] = []
    for c in ranked:
        bits = [c.severity.lower()]
        if c.kev:
            bits.append("CISA KEV match")
        if c.instances > 1:
            bits.append(f"{c.instances} callsites")
        if len(c.files) > 1:
            bits.append(f"{len(c.files)} files affected")
        reason = ", ".join(bits) + "."
        out.append({"cluster_key": c.key, "reason": reason.capitalize()})
    return out


_SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


def _sev_priority(sev: str) -> int:
    try:
        return _SEV_ORDER.index(sev)
    except ValueError:
        return len(_SEV_ORDER)


def _profile_blob(profile) -> dict:
    if not profile:
        return {}
    if isinstance(profile, dict):
        return {k: profile.get(k) for k in ("languages", "package_managers", "frameworks", "iac") if profile.get(k)}
    return {
        "languages": getattr(profile, "languages", None),
        "package_managers": getattr(profile, "package_managers", None),
        "frameworks": getattr(profile, "frameworks", None),
        "iac": getattr(profile, "iac", None),
    }
