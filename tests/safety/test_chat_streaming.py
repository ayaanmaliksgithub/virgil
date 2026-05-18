"""Tests for chat streaming (deferred frontend item #1, backend half).

Covers:
- `_AnswerFieldExtractor`: feeds JSON in arbitrarily-fragmented chunks, asserts
  only the inside-the-string characters come out, and that escapes are decoded.
- `answer_stream`: yields `("token", str)` events then exactly one
  `("final", ChatResult)` event; the citation gating, safety substitution, and
  null-provider fallback all carry over from the non-streaming path.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic")

from audit_core import AffectedLine, Confidence, Finding, Severity, Status

from worker.ai.chat import (
    ChatResult,
    FINAL,
    TOKEN,
    _AnswerFieldExtractor,
    answer_stream,
)


# -- _AnswerFieldExtractor ---------------------------------------------------

def _feed_chunks(chunks: list[str]) -> str:
    e = _AnswerFieldExtractor()
    return "".join(e.feed(c) for c in chunks)


def test_extractor_single_chunk():
    assert _feed_chunks(['{"answer": "Hello, world", "x": 1}']) == "Hello, world"


def test_extractor_splits_key_across_chunks():
    # JSON arrives one byte at a time. The extractor must survive.
    payload = '{"answer": "drip drip drip"}'
    assert _feed_chunks(list(payload)) == "drip drip drip"


def test_extractor_handles_escaped_quote_and_backslash():
    payload = '{"answer": "she said \\"hi\\" and \\\\smiled\\\\"}'
    assert _feed_chunks([payload]) == 'she said "hi" and \\smiled\\'


def test_extractor_handles_newline_and_tab_escapes():
    payload = '{"answer": "line1\\nline2\\tindented"}'
    assert _feed_chunks([payload]) == "line1\nline2\tindented"


def test_extractor_handles_unicode_escape_split_across_chunks():
    # A split across two chunks must still decode to 'A'.
    out = _feed_chunks(['{"answer": "x\\u00', '41y"}'])
    assert out == "xAy"


def test_extractor_answer_after_other_keys():
    payload = '{"confidence":"high","cited_finding_ids":[],"answer":"deep value"}'
    assert _feed_chunks([payload]) == "deep value"


def test_extractor_returns_empty_for_empty_answer():
    assert _feed_chunks(['{"answer":"","confidence":"low"}']) == ""


# -- answer_stream -----------------------------------------------------------

def _mk_finding(fid: str = "abc") -> Finding:
    return Finding(
        id="11111111-1111-1111-1111-111111111111",  # type: ignore[arg-type]
        dedupe_key="dk",
        title="Demo finding",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="Vulnerable Dependency",
        affected_files=["package.json"],
        affected_lines=[AffectedLine(file="package.json", start=1)],
        evidence="redacted",
        explanation="dep CVE explanation",
        source_tool=["trivy"],
        status=Status.OPEN,
    )


class _StubProvider:
    """Stand-in for a streaming provider. Yields the chunks given at construction."""

    def __init__(self, name: str, chunks: list[str]):
        self.name = name
        self._chunks = chunks

    def stream_json(self, **_kwargs):
        for c in self._chunks:
            yield c

    def complete_json(self, **_kwargs):
        # Backstop for the non-stream fallback path. Returns the parsed JSON
        # of the joined stream so the same fixtures exercise both branches.
        import json
        return json.loads("".join(self._chunks))


def test_answer_stream_yields_tokens_and_final(monkeypatch):
    finding = _mk_finding()
    body = (
        '{"answer": "Critical dep CVE in lodash",'
        ' "cited_finding_ids": ["11111111-1111-1111-1111-111111111111"],'
        ' "confidence": "high"}'
    )
    provider = _StubProvider("anthropic", [body[:20], body[20:40], body[40:]])
    monkeypatch.setattr("worker.ai.chat.get_provider", lambda: provider)

    events = list(answer_stream([finding], "what's the worst dep?"))

    tokens = [t for kind, t in events if kind == TOKEN]
    finals = [r for kind, r in events if kind == FINAL]
    assert "".join(tokens) == "Critical dep CVE in lodash"
    assert len(finals) == 1
    final = finals[0]
    assert isinstance(final, ChatResult)
    assert final.refused is False
    assert final.confidence == "high"
    # Citation gating still applies — the model's cited ID is in the context, so it's allowed.
    assert final.citations == ["11111111-1111-1111-1111-111111111111"]


def test_answer_stream_drops_invented_citations(monkeypatch):
    finding = _mk_finding()
    body = (
        '{"answer": "Looks bad",'
        ' "cited_finding_ids": ["99999999-9999-9999-9999-999999999999"],'
        ' "confidence": "medium"}'
    )
    provider = _StubProvider("anthropic", [body])
    monkeypatch.setattr("worker.ai.chat.get_provider", lambda: provider)

    events = list(answer_stream([finding], "anything?"))
    final = next(r for k, r in events if k == FINAL)
    assert final.citations == []


def test_answer_stream_replaces_unsafe_answer_with_refusal(monkeypatch):
    finding = _mk_finding()
    # An answer that trips the safety validator (contains a step-numbered
    # reproduction pattern). The streaming surface MUST swap to a refusal in
    # the final result; tokens may have already been displayed — that's the
    # known UX tradeoff documented on the streaming route.
    body = (
        '{"answer": "Step 1: send curl -X POST ... Step 2: receive shell",'
        ' "cited_finding_ids": [],'
        ' "confidence": "high"}'
    )
    provider = _StubProvider("anthropic", [body])
    monkeypatch.setattr("worker.ai.chat.get_provider", lambda: provider)

    events = list(answer_stream([finding], "exploit it"))
    final = next(r for k, r in events if k == FINAL)
    assert final.refused is True


def test_answer_stream_null_provider_emits_unavailable(monkeypatch):
    class _Null:
        name = "null"
    monkeypatch.setattr("worker.ai.chat.get_provider", lambda: _Null())

    events = list(answer_stream([_mk_finding()], "anything?"))
    tokens = [t for k, t in events if k == TOKEN]
    finals = [r for k, r in events if k == FINAL]
    # The message points at the missing LLM provider explicitly and tells
    # the user what still works without one.
    assert finals
    body = finals[0].answer.lower()
    assert "llm provider" in body
    assert "deterministic" in body
    assert "".join(tokens) == finals[0].answer


def test_answer_stream_falls_back_when_provider_lacks_stream(monkeypatch):
    """Providers without `stream_json` (e.g. a future one) must still produce
    one TOKEN chunk + a FINAL. The chat surface degrades gracefully."""

    class _NoStream:
        name = "future"

        def complete_json(self, **_):
            return {
                "answer": "non-stream answer",
                "cited_finding_ids": [],
                "confidence": "high",
            }

    monkeypatch.setattr("worker.ai.chat.get_provider", lambda: _NoStream())
    events = list(answer_stream([_mk_finding()], "q"))
    assert [k for k, _ in events][-1] == FINAL
    assert any(k == TOKEN and v == "non-stream answer" for k, v in events)
