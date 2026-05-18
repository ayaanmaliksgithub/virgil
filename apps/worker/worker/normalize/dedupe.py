"""Deduplicate findings reported by multiple tools or rules.

Strategy:
- Compute dedupe_key from (normalized_rule_id, file, start_line, snippet_hash).
- Group by key; merge:
  * source_tool list (union)
  * affected_files / affected_lines (union)
  * severity = max
  * confidence = max (higher when multiple independent tools agree)
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

from audit_core import (
    CONFIDENCE_ORDER,
    SEVERITY_ORDER,
    AffectedLine,
    Confidence,
    Finding,
    Severity,
)

_RULE_PREFIX_STRIP = re.compile(r"^[a-z]+/")


def make_dedupe_key(rule_id: str, file: str, start_line: int, snippet: str | None) -> str:
    normalized_rule = _RULE_PREFIX_STRIP.sub("", rule_id.lower())
    base = f"{normalized_rule}|{file}|{start_line}|{_snippet_hash(snippet)}"
    return hashlib.sha256(base.encode()).hexdigest()[:32]


def _snippet_hash(snippet: str | None) -> str:
    if not snippet:
        return "-"
    return hashlib.sha256(snippet.strip().encode()).hexdigest()[:12]


def _max_severity(a: Severity, b: Severity) -> Severity:
    return a if SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] else b


def _max_confidence(a: Confidence, b: Confidence) -> Confidence:
    return a if CONFIDENCE_ORDER[a] >= CONFIDENCE_ORDER[b] else b


def dedupe(findings: Iterable[Finding]) -> list[Finding]:
    by_key: dict[str, Finding] = {}
    for f in findings:
        existing = by_key.get(f.dedupe_key)
        if existing is None:
            by_key[f.dedupe_key] = f
            continue

        merged_tools = sorted(set(existing.source_tool) | set(f.source_tool))
        merged_files = sorted(set(existing.affected_files) | set(f.affected_files))
        merged_lines = _merge_lines(existing.affected_lines, f.affected_lines)

        # Independent tool agreement → bump confidence to HIGH.
        agree = len(merged_tools) >= 2
        new_conf = _max_confidence(
            Confidence(existing.confidence) if isinstance(existing.confidence, str) else existing.confidence,
            Confidence(f.confidence) if isinstance(f.confidence, str) else f.confidence,
        )
        if agree:
            new_conf = Confidence.HIGH

        sev_a = Severity(existing.severity) if isinstance(existing.severity, str) else existing.severity
        sev_b = Severity(f.severity) if isinstance(f.severity, str) else f.severity

        merged = existing.model_copy(update={
            "source_tool": merged_tools,
            "affected_files": merged_files,
            "affected_lines": merged_lines,
            "severity": _max_severity(sev_a, sev_b),
            "confidence": new_conf,
            "cwe": existing.cwe or f.cwe,
            "cve": existing.cve or f.cve,
            "owasp_category": existing.owasp_category or f.owasp_category,
        })
        by_key[f.dedupe_key] = merged
    return list(by_key.values())


def _merge_lines(a: list[AffectedLine], b: list[AffectedLine]) -> list[AffectedLine]:
    seen: set[tuple[str, int, int | None]] = set()
    out: list[AffectedLine] = []
    for line in [*a, *b]:
        key = (line.file, line.start, line.end)
        if key in seen:
            continue
        seen.add(key)
        out.append(line)
    return out
