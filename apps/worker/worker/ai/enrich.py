"""Per-finding LLM enrichment.

Adds `explanation`, `exploitability_summary`, `business_impact`, and
`safe_guidance` (high-level only) to each normalized finding. Inputs are
redacted before they reach the model; outputs are sanity-checked by the safety
validator before they are accepted.
"""
from __future__ import annotations

import json
import logging

from typing import Callable
from audit_core import Finding, RepoProfile

from worker.ai.prompts.system import AUDITOR_SYSTEM
from worker.ai.provider import get_provider
from worker.ai.safety import sanitize
from worker.normalize.redact import safe_for_llm

log = logging.getLogger(__name__)

FINDING_ENRICHMENT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["explanation", "business_impact", "safe_guidance", "exploitability_summary"],
    "properties": {
        "explanation": {"type": "string", "maxLength": 1200},
        "business_impact": {"type": "string", "maxLength": 800},
        "safe_guidance": {"type": "string", "maxLength": 800},
        "exploitability_summary": {"type": "string", "maxLength": 600},
    },
}

DEFENSIVE_FALLBACK = (
    "Defensive guidance withheld pending manual review. Refer to your security "
    "team and the relevant control framework (OWASP ASVS, NIST SSDF) before "
    "acting on this finding."
)


def enrich_findings(findings: list[Finding], *, profile: RepoProfile, progress_cb: Callable[[int, int], None] | None = None) -> list[Finding]:
    provider = get_provider()
    if provider.name == "null":
        return findings  # graceful degradation

    profile_blob = {
        "languages": profile.languages,
        "package_managers": profile.package_managers,
        "frameworks": profile.frameworks,
        "iac": profile.iac,
    }

    out: list[Finding] = []
    total = len(findings)
    for i, f in enumerate(findings, 1):
        user = _build_user_prompt(f, profile_blob)
        try:
            data = provider.complete_json(
                system=AUDITOR_SYSTEM,
                user=user,
                schema=FINDING_ENRICHMENT_SCHEMA,
                max_tokens=900,
                temperature=0.2,
            )
        except Exception as e:
            log.warning("enrichment failed for %s: %s", f.id, e)
            out.append(f)
            continue

        explanation = sanitize(data.get("explanation"), fallback=f.explanation or "")
        business_impact = sanitize(data.get("business_impact"), fallback="")
        exploitability = sanitize(data.get("exploitability_summary"), fallback="")
        guidance = sanitize(data.get("safe_guidance"), fallback=DEFENSIVE_FALLBACK)

        out.append(f.model_copy(update={
            "explanation": explanation or f.explanation,
            "business_impact": business_impact or None,
            "exploitability_summary": exploitability or None,
            "safe_guidance": guidance,
        }))
        if progress_cb is not None:
            try:
                progress_cb(i, total)
            except Exception:
                pass
    return out


def _build_user_prompt(f: Finding, profile_blob: dict) -> str:
    finding_view = {
        "title": f.title,
        "severity": f.severity if isinstance(f.severity, str) else f.severity.value,
        "category": f.category,
        "owasp_category": f.owasp_category,
        "cwe": f.cwe,
        "cve": f.cve,
        "affected_files": f.affected_files,
        "affected_lines": [al.model_dump() for al in f.affected_lines],
        "evidence_redacted": safe_for_llm(f.evidence),
        "scanner_message_redacted": safe_for_llm(f.explanation),
        "source_tool": f.source_tool,
    }
    # `code_context` is already pre-redacted by worker.normalize.code_context;
    # it's a ~30-line slice with 1-indexed line numbers (e.g. " 42  return x").
    # Pass it through verbatim so the LLM can reference specific lines and
    # judge whether surrounding code already mitigates the issue. The audit
    # safety contract still holds — no payloads/diffs/steps in the output.
    code_block = ""
    if f.code_context:
        code_block = (
            "\n\nCode context (redacted, 1-indexed line numbers — the offending "
            f"line is {f.affected_lines[0].start if f.affected_lines else '?'}):\n"
            f"```\n{f.code_context}\n```"
        )

    return (
        "Repository profile (high-level only):\n"
        f"{json.dumps(profile_blob)}\n\n"
        "Scanner-grounded finding (already deterministic):\n"
        f"{json.dumps(finding_view)}"
        f"{code_block}\n\n"
        "Task: Produce the JSON object described in the schema.\n"
        "- 'explanation': what this issue is, in plain language, grounded in\n"
        "  the evidence AND the code context. When code context is provided,\n"
        "  refer to specific line numbers and variable names from it — do\n"
        "  NOT speak in generic terms when the code is right there.\n"
        "- 'business_impact': realistic risk to the organization. No reproduction.\n"
        "- 'exploitability_summary': high-level only. If the code context\n"
        "  shows surrounding mitigations (input validation upstream, parameterized\n"
        "  queries, etc.) say so plainly. No payloads, no steps.\n"
        "- 'safe_guidance': HIGH-LEVEL defensive direction only. No patches, no\n"
        "  commands, no step-by-step. Two short sentences max.\n"
    )
