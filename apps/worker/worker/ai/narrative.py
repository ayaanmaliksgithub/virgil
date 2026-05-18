"""Executive-summary / attack-surface narrative.

Single LLM call after enrichment. Output is plain prose, run through the
safety validator. No findings are invented — the LLM only summarizes the list
that was already produced by deterministic scanners.
"""
from __future__ import annotations

import json
import logging
from collections import Counter

from audit_core import Finding, RepoProfile

from worker.ai.prompts.system import AUDITOR_SYSTEM
from worker.ai.provider import get_provider
from worker.ai.safety import sanitize

log = logging.getLogger(__name__)

NARRATIVE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["executive_summary", "attack_surface"],
    "properties": {
        "executive_summary": {"type": "string", "maxLength": 1200},
        "attack_surface": {"type": "string", "maxLength": 1200},
    },
}


def build_narrative(findings: list[Finding], *, profile: RepoProfile) -> str:
    provider = get_provider()
    if provider.name == "null" or not findings:
        return ""

    counts = Counter(
        (f.severity if isinstance(f.severity, str) else f.severity.value)
        for f in findings
    )
    categories = Counter(f.category for f in findings).most_common(8)
    titles = [f.title for f in findings[:25]]

    user = (
        "Repository profile (high-level only):\n"
        f"{json.dumps({'languages': profile.languages, 'package_managers': profile.package_managers, 'frameworks': profile.frameworks, 'iac': profile.iac})}\n\n"
        "Severity counts:\n"
        f"{json.dumps(counts)}\n\n"
        "Top categories:\n"
        f"{json.dumps(categories)}\n\n"
        "Sample finding titles:\n"
        f"{json.dumps(titles)}\n\n"
        "Task: Produce the JSON described in the schema.\n"
        "- 'executive_summary' is plain-language risk overview for non-technical readers.\n"
        "- 'attack_surface' is a short narrative describing the categories of exposure\n"
        "  (secrets, auth, API, dependencies, infrastructure) found in this codebase.\n"
        "Do NOT include payloads, code, or reproduction steps. Do not invent findings\n"
        "that are not represented in the inputs above.\n"
    )
    try:
        data = provider.complete_json(
            system=AUDITOR_SYSTEM,
            user=user,
            schema=NARRATIVE_SCHEMA,
            max_tokens=1200,
            temperature=0.2,
        )
    except Exception as e:
        log.warning("narrative generation failed: %s", e)
        return ""

    summary = sanitize(data.get("executive_summary"), fallback="")
    surface = sanitize(data.get("attack_surface"), fallback="")
    if not summary and not surface:
        return ""
    return f"{summary}\n\nAttack surface: {surface}".strip()
