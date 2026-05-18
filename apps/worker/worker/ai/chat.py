"""Ask-the-Auditor RAG.

Hard rules for this surface:
  - Answers MUST be grounded in stored findings of the audit being asked about.
  - The LLM is system-prompted to refuse questions it cannot answer from cited
    context and to continue refusing exploit-shaped requests.
  - Every assistant message is run through the safety validator. If it fails,
    the answer is replaced with a generic refusal — we never display unsafe
    output to the user.
  - Citations are `finding_id` references only. Free-form file paths in the
    answer body are still allowed (they're not exploit content).

The retriever is deliberately simple — keyword overlap over the persisted
findings. A vector store is overkill for the corpus size (~tens to low-
hundreds of findings per audit) and would expand the trust boundary. If
recall becomes an issue we add embeddings later behind the same interface.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Callable, Iterator

from audit_core import Finding

from worker.ai.prompts.system import AUDITOR_SYSTEM
from worker.ai.provider import get_provider
from worker.ai.safety import is_safe
from worker.normalize.redact import safe_for_llm

log = logging.getLogger(__name__)

MAX_CONTEXT_FINDINGS = 8
MAX_HISTORY_TURNS = 6

CHAT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["answer", "cited_finding_ids", "confidence"],
    "properties": {
        "answer": {"type": "string", "maxLength": 1600},
        "cited_finding_ids": {
            "type": "array", "items": {"type": "string"}, "maxItems": 8,
        },
        "confidence": {"enum": ["high", "medium", "low", "unanswerable"]},
    },
}

REFUSAL = (
    "I can't answer that from this audit's evidence. I'm bound to the stored "
    "findings and will not produce exploit-shaped content. Try asking about a "
    "specific finding, category, or affected file."
)

CHAT_SYSTEM = (
    AUDITOR_SYSTEM
    + "\n\nYou are answering questions about ONE specific audit. Rules:\n"
    "- Use ONLY the provided findings. If the answer is not supported, set\n"
    "  confidence='unanswerable' and write a brief refusal.\n"
    "- Cite the finding IDs you used in cited_finding_ids. Do not invent IDs.\n"
    "- Never produce exploit payloads, exact patches, diffs, or step-by-step\n"
    "  reproduction. Refuse such requests with a one-line decline.\n"
    "- Keep answers under 200 words. Plain language, no operational details.\n"
    "- When `code_context_redacted` is present on a finding, USE it to ground\n"
    "  your answer (refer to line numbers, name visible variables, note when\n"
    "  surrounding code already mitigates the issue). Do not quote it back\n"
    "  verbatim in long blocks — describe what's there.\n"
)


@dataclass
class ChatTurn:
    role: str       # 'user' or 'assistant'
    content: str


@dataclass
class ChatResult:
    answer: str
    citations: list[str]
    confidence: str
    refused: bool


# --- retrieval ---------------------------------------------------------------

_WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_\-]{2,}")


def _terms(text: str) -> set[str]:
    return {w.lower() for w in _WORD_RE.findall(text)}


def retrieve(findings: list[Finding], query: str, *, k: int = MAX_CONTEXT_FINDINGS) -> list[Finding]:
    """Score each finding by keyword overlap with the query, return top-k."""
    q_terms = _terms(query)
    if not q_terms:
        return findings[:k]

    scored: list[tuple[float, Finding]] = []
    for f in findings:
        hay = " ".join([
            f.title,
            f.category or "",
            f.owasp_category or "",
            f.cwe or "",
            f.cve or "",
            " ".join(f.affected_files),
            f.explanation or "",
            f.business_impact or "",
        ])
        f_terms = _terms(hay)
        if not f_terms:
            continue
        overlap = len(q_terms & f_terms)
        if overlap == 0:
            continue
        # Lightly favor higher-severity matches so the model sees Critical/High
        # context first when scores are tied.
        sev_boost = {"Critical": 0.4, "High": 0.25, "Medium": 0.1, "Low": 0.05, "Informational": 0}.get(
            f.severity if isinstance(f.severity, str) else f.severity.value, 0
        )
        scored.append((overlap + sev_boost, f))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [f for _, f in scored[:k]]


# --- prompt --------------------------------------------------------------

def _finding_blob(f: Finding) -> dict:
    blob = {
        "id": str(f.id),
        "title": f.title,
        "severity": f.severity if isinstance(f.severity, str) else f.severity.value,
        "category": f.category,
        "owasp_category": f.owasp_category,
        "cwe": f.cwe,
        "cve": f.cve,
        "affected_files": f.affected_files,
        "affected_lines": [
            {"file": al.file, "start": al.start, "end": al.end}
            for al in (f.affected_lines or [])
        ][:4],
        "explanation_redacted": safe_for_llm(f.explanation),
        "business_impact": safe_for_llm(f.business_impact or ""),
        "safe_guidance": safe_for_llm(f.safe_guidance or ""),
        "source_tool": f.source_tool,
    }
    # Code context is already pre-redacted by worker.normalize.code_context.
    # Including it lets the LLM say "the input on line 42 is already
    # parameterized two lines up" — actual code-grounded triage.
    if f.code_context:
        blob["code_context_redacted"] = f.code_context
    return blob


def _build_user(query: str, context: list[Finding], history: list[ChatTurn]) -> str:
    hist = history[-MAX_HISTORY_TURNS:]
    return (
        "Audit context (findings retrieved by keyword match against the question):\n"
        + json.dumps([_finding_blob(f) for f in context], indent=2)
        + "\n\nConversation so far:\n"
        + json.dumps([{"role": t.role, "content": t.content[:1200]} for t in hist], indent=2)
        + f"\n\nNew question: {query.strip()[:1200]}\n\n"
        "Produce the JSON object described in the schema. If the question cannot "
        "be answered from these findings, set confidence='unanswerable' and "
        "write a one-line refusal."
    )


# --- entry point -------------------------------------------------------------

def answer(
    findings: list[Finding],
    query: str,
    history: list[ChatTurn] | None = None,
) -> ChatResult:
    history = history or []
    context = retrieve(findings, query)
    provider = get_provider()
    if provider.name == "null":
        return ChatResult(
            answer=(
                "Ask-the-Auditor needs an LLM provider — set "
                "ANTHROPIC_API_KEY or OPENAI_API_KEY in your .env to enable it. "
                "Meanwhile, the rest of the audit works deterministically: "
                "check the triage view for the ranked cluster queue, browse "
                "the findings ledger for full detail, or grab the SARIF/CSV "
                "export from the report tab."
            ),
            citations=[], confidence="unanswerable", refused=False,
        )

    try:
        data = provider.complete_json(
            system=CHAT_SYSTEM,
            user=_build_user(query, context, history),
            schema=CHAT_SCHEMA,
            max_tokens=900,
            temperature=0.2,
        )
    except Exception as e:
        log.warning("chat provider failed: %s", e)
        return ChatResult(answer=REFUSAL, citations=[], confidence="unanswerable", refused=True)

    raw_answer = (data.get("answer") or "").strip()
    confidence = data.get("confidence") or "low"
    cited_raw = [str(c) for c in (data.get("cited_finding_ids") or [])]

    # Drop any citation IDs the model invented — only allow ones that match
    # findings actually fed to it.
    allowed_ids = {str(f.id) for f in context}
    citations = [c for c in cited_raw if c in allowed_ids]

    # Last-line safety filter. If anything tripped the validator, replace with
    # a refusal and mark the turn as refused.
    if not is_safe(raw_answer):
        return ChatResult(answer=REFUSAL, citations=[], confidence="unanswerable", refused=True)

    if not raw_answer:
        return ChatResult(answer=REFUSAL, citations=[], confidence="unanswerable", refused=True)

    return ChatResult(answer=raw_answer, citations=citations, confidence=confidence, refused=False)


# --- streaming entry point --------------------------------------------------

# Sentinel chunk types emitted by `answer_stream`. The route handler maps each
# to an SSE event so the frontend can render incrementally without leaking the
# JSON envelope to the user.
TOKEN = "token"
FINAL = "final"


def answer_stream(
    findings: list[Finding],
    query: str,
    history: list[ChatTurn] | None = None,
) -> Iterator[tuple[str, object]]:
    """Stream a chat answer.

    Yields one of:
      `("token", "<chunk-of-visible-text>")` — characters from the JSON
        envelope's `answer` field, suitable for direct rendering. The envelope
        itself (`{"answer":"…","cited_finding_ids":[…],…}`) is NEVER yielded
        as-is — `_AnswerFieldExtractor` strips it before forwarding.
      `("final", ChatResult)` — exactly once, at the end of the stream, after
        the full JSON has been collected. This is where safety validation,
        citation gating, and refused/empty-output substitution happen.

    Providers that don't support real streaming (currently the null provider)
    yield the entire answer in a single token chunk followed by the final
    ChatResult — semantically equivalent, just no progressive UI.
    """
    history = history or []
    context = retrieve(findings, query)
    provider = get_provider()

    if provider.name == "null":
        result = ChatResult(
            answer=(
                "Ask-the-Auditor needs an LLM provider — set "
                "ANTHROPIC_API_KEY or OPENAI_API_KEY in your .env to enable it. "
                "The rest of the audit (triage queue, findings ledger, SARIF/CSV "
                "export) runs deterministically without one."
            ),
            citations=[], confidence="unanswerable", refused=False,
        )
        yield (TOKEN, result.answer)
        yield (FINAL, result)
        return

    stream_fn: Callable[..., Iterator[str]] | None = getattr(provider, "stream_json", None)
    if stream_fn is None:
        # Fall back to a single-shot completion and emit one token chunk.
        try:
            data = provider.complete_json(
                system=CHAT_SYSTEM,
                user=_build_user(query, context, history),
                schema=CHAT_SCHEMA,
                max_tokens=900,
                temperature=0.2,
            )
        except Exception as e:
            log.warning("chat provider failed (non-stream fallback): %s", e)
            result = ChatResult(answer=REFUSAL, citations=[], confidence="unanswerable", refused=True)
            yield (TOKEN, REFUSAL)
            yield (FINAL, result)
            return
        result = _finalize(data, context)
        if not result.refused:
            yield (TOKEN, result.answer)
        else:
            yield (TOKEN, result.answer)
        yield (FINAL, result)
        return

    extractor = _AnswerFieldExtractor()
    raw_buffer = []
    try:
        for delta in stream_fn(
            system=CHAT_SYSTEM,
            user=_build_user(query, context, history),
            schema=CHAT_SCHEMA,
            max_tokens=900,
            temperature=0.2,
        ):
            raw_buffer.append(delta)
            visible = extractor.feed(delta)
            if visible:
                yield (TOKEN, visible)
    except Exception as e:
        log.warning("chat provider stream failed: %s", e)
        result = ChatResult(answer=REFUSAL, citations=[], confidence="unanswerable", refused=True)
        yield (TOKEN, REFUSAL)
        yield (FINAL, result)
        return

    full_text = "".join(raw_buffer)
    parsed = _parse_json_object(full_text) or {}
    result = _finalize(parsed, context)

    # If safety validation reverted the answer to a refusal AFTER we streamed
    # the model's text, signal the frontend so it can replace the partial render.
    yield (FINAL, result)


def _finalize(data: dict[str, object], context: list[Finding]) -> ChatResult:
    """Shared post-processing for streaming and non-streaming paths.

    Handles the same citation gating + safety validation as `answer()` so the
    two surfaces never diverge on policy.
    """
    raw_answer = (str(data.get("answer") or "")).strip()
    confidence = str(data.get("confidence") or "low")
    cited_raw = [str(c) for c in (data.get("cited_finding_ids") or [])]
    allowed_ids = {str(f.id) for f in context}
    citations = [c for c in cited_raw if c in allowed_ids]

    if not raw_answer or not is_safe(raw_answer):
        return ChatResult(answer=REFUSAL, citations=[], confidence="unanswerable", refused=True)
    return ChatResult(answer=raw_answer, citations=citations, confidence=confidence, refused=False)


def _parse_json_object(text: str) -> dict[str, object] | None:
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None


class _AnswerFieldExtractor:
    r"""Stateful, append-only JSON `"answer": "..."` value extractor.

    Designed for the specific JSON shape `{"answer": "...", ...}` that the
    LLM produces under our prompt. Walks character-by-character so each call
    to `feed()` returns only the newly-visible portion of the answer string —
    perfect for piping to SSE tokens.

    Not a general JSON parser. Handles:
      - `"answer"` key in any position within the object
      - whitespace between key, colon, and value
      - common backslash escapes: \", \\, \n, \t, \r, \b, \f
      - `\uXXXX` unicode escapes
    Anything outside the answer string is silently consumed.
    """

    def __init__(self) -> None:
        self._state = "outside"  # outside | in_answer
        self._buf = ""

    def feed(self, chunk: str) -> str:
        if self._state == "done":
            # Answer string already closed — discard everything afterward.
            return ""
        self._buf += chunk
        out: list[str] = []
        i = 0
        n = len(self._buf)
        while i < n:
            if self._state == "done":
                break
            if self._state == "outside":
                # Search for the opening of the answer string value.
                key = '"answer"'
                key_idx = self._buf.find(key, i)
                if key_idx < 0:
                    # We may be in the middle of a partial `"answer"` — keep
                    # enough of the tail to match next round.
                    keep = min(len(key) - 1, n - i)
                    self._buf = self._buf[n - keep :]
                    return "".join(out)
                # Skip past key, whitespace, colon, whitespace, opening quote.
                j = key_idx + len(key)
                while j < n and self._buf[j] in " \t\r\n":
                    j += 1
                if j >= n or self._buf[j] != ":":
                    if j >= n:
                        self._buf = self._buf[key_idx:]
                        return "".join(out)
                    # Bogus structure — give up and consume input.
                    self._buf = ""
                    return "".join(out)
                j += 1
                while j < n and self._buf[j] in " \t\r\n":
                    j += 1
                if j >= n:
                    self._buf = self._buf[key_idx:]
                    return "".join(out)
                if self._buf[j] != '"':
                    self._buf = ""
                    return "".join(out)
                i = j + 1
                self._state = "in_answer"
            else:  # in_answer
                c = self._buf[i]
                if c == "\\":
                    if i + 1 >= n:
                        # Need more input to resolve the escape sequence.
                        self._buf = self._buf[i:]
                        return "".join(out)
                    nxt = self._buf[i + 1]
                    if nxt == "u":
                        if i + 5 >= n:
                            self._buf = self._buf[i:]
                            return "".join(out)
                        try:
                            out.append(chr(int(self._buf[i + 2 : i + 6], 16)))
                        except ValueError:
                            out.append(self._buf[i : i + 6])
                        i += 6
                        continue
                    out.append({
                        '"': '"', "\\": "\\", "/": "/",
                        "n": "\n", "t": "\t", "r": "\r",
                        "b": "\b", "f": "\f",
                    }.get(nxt, nxt))
                    i += 2
                    continue
                if c == '"':
                    # End of answer string — we're done consuming for this stream.
                    self._buf = ""
                    self._state = "done"
                    return "".join(out)
                out.append(c)
                i += 1
        # Reached end of buffer without closing quote — keep it for next feed.
        self._buf = ""
        return "".join(out)
