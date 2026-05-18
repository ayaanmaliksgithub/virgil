"""Pins the contract that per-finding LLM enrichment uses code context
when present.

Without this test, a future refactor could silently drop `code_context`
from the prompt and the user-visible quality of `explanation` /
`safe_guidance` would regress without any signal.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic")

from audit_core import AffectedLine, Confidence, Finding, Severity, Status
from worker.ai.enrich import _build_user_prompt


def _f(code_context: str | None = None, line: int = 42) -> Finding:
    return Finding(
        dedupe_key="dk-1",
        title="SQL injection",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="Injection",
        cwe="CWE-89",
        affected_files=["src/app.py"],
        affected_lines=[AffectedLine(file="src/app.py", start=line)],
        evidence="user input",
        explanation="raw sql interpolation",
        source_tool=["semgrep"],
        code_context=code_context,
        status=Status.OPEN,
    )


def test_prompt_omits_code_block_when_no_context():
    out = _build_user_prompt(_f(code_context=None), {})
    assert "Code context" not in out
    assert "```" not in out


def test_prompt_includes_code_block_when_context_present():
    ctx = "40  ctx = build()\n41  q = make_query(user)\n42  db.execute(q)"
    out = _build_user_prompt(_f(code_context=ctx, line=42), {})
    assert "Code context" in out
    assert "the offending line is 42" in out
    # The code block is delimited so the model knows where context ends.
    assert "```\n40  ctx = build()" in out


def test_prompt_instructs_model_to_reference_lines_and_variables():
    out = _build_user_prompt(_f(code_context="42  x = 1"), {})
    assert "specific line numbers" in out
    assert "variable names" in out


def test_prompt_instructs_model_to_acknowledge_upstream_mitigations():
    out = _build_user_prompt(_f(code_context="42  x = 1"), {})
    # The "surrounding mitigations" clause is what gives us the
    # "actually this is fine because input is parameterized upstream" answer.
    assert "mitigations" in out.lower()
