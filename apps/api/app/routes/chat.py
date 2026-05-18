"""Ask-the-Auditor chat endpoint.

POST /v1/audits/:id/chat
  body: { "session_id"?: uuid, "message": "string" }
  returns: { session_id, message, history }

Sessions persist in `chat_sessions` / `chat_messages`. The RAG call itself
lives in `worker.ai.chat` so that the safety controls share a single source
of truth with finding enrichment.
"""
from __future__ import annotations

import logging
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Audit, ChatMessage, ChatSession, FindingRow
from app.db.session import get_db

log = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/audits", tags=["chat"])

MAX_MESSAGE_CHARS = 2000


class ChatRequest(BaseModel):
    session_id: UUID | None = None
    message: str = Field(min_length=1, max_length=MAX_MESSAGE_CHARS)


class ChatTurnOut(BaseModel):
    id: UUID
    role: str
    content: str
    citations: list[str]
    created_at: str


class ChatResponse(BaseModel):
    session_id: UUID
    message: ChatTurnOut
    history: list[ChatTurnOut]


@router.get("/{audit_id}/chat/suggested")
def get_suggested_questions(audit_id: UUID, db: Session = Depends(get_db)) -> dict:
    """Three concrete chat prompts derived from this audit's top clusters.

    UI uses these to seed the chat input — clicking a suggestion pre-fills
    the textarea. Deterministic (no LLM), so it's instant and free.
    """
    from app.services.suggested_questions import suggested_questions

    audit = db.get(Audit, audit_id)
    if not audit:
        raise HTTPException(404, "audit not found")
    rows = db.execute(
        select(FindingRow).where(FindingRow.audit_id == audit_id)
    ).scalars().all()
    return {"items": suggested_questions(audit, list(rows))}


@router.post("/{audit_id}/chat", response_model=ChatResponse)
def post_chat(audit_id: UUID, body: ChatRequest, db: Session = Depends(get_db)) -> ChatResponse:
    # Local import keeps the API container slim if the worker isn't installed —
    # in compose they share the venv, so this is essentially free.
    from worker.ai.chat import ChatTurn, answer as ask
    from audit_core import Finding, AffectedLine

    audit = db.get(Audit, audit_id)
    if not audit:
        raise HTTPException(404, "audit not found")

    session = _resolve_session(db, audit_id, body.session_id)

    # Persist the user's turn first so the conversation is on disk even if
    # the LLM call later fails.
    user_msg = ChatMessage(session_id=session.id, role="user", content=body.message.strip(), citations=[])
    db.add(user_msg)
    db.commit()
    db.refresh(user_msg)

    # Load history (excluding the just-added user turn — we pass `query` separately).
    history_rows = db.execute(
        select(ChatMessage)
        .where(ChatMessage.session_id == session.id)
        .order_by(ChatMessage.created_at.asc())
    ).scalars().all()
    history = [
        ChatTurn(role=r.role, content=r.content)
        for r in history_rows
        if r.id != user_msg.id
    ]

    # Load this audit's findings and reconstruct the canonical Finding objects.
    rows = db.execute(
        select(FindingRow).where(FindingRow.audit_id == audit_id)
    ).scalars().all()
    findings = [_row_to_finding(r) for r in rows]

    if not findings:
        result_text = "This audit has no findings on file, so there's nothing for me to ground an answer in."
        result_citations: list[str] = []
    else:
        result = ask(findings, body.message, history=history)
        result_text = result.answer
        result_citations = result.citations

    assistant_msg = ChatMessage(
        session_id=session.id,
        role="assistant",
        content=result_text,
        citations=result_citations,
    )
    db.add(assistant_msg)
    db.commit()
    db.refresh(assistant_msg)

    history_out = db.execute(
        select(ChatMessage)
        .where(ChatMessage.session_id == session.id)
        .order_by(ChatMessage.created_at.asc())
    ).scalars().all()

    return ChatResponse(
        session_id=session.id,
        message=_to_out(assistant_msg),
        history=[_to_out(m) for m in history_out],
    )


@router.post("/{audit_id}/chat/stream")
def post_chat_stream(audit_id: UUID, body: ChatRequest, db: Session = Depends(get_db)):
    """Streaming variant of `POST /chat`.

    Returns Server-Sent Events. Frame schedule:
      `event: session` `data: {"session_id": "..."}`         — once, up front
      `event: token`   `data: {"text": "..."}`                — many; the visible
                                                                 portion of the answer
      `event: done`    `data: {"message": {...}, "history": [...], "refused": bool}`
      `event: error`   `data: {"detail": "..."}`              — only on failure

    The user message is persisted BEFORE the stream opens so a dropped
    connection doesn't lose the prompt. Safety validation runs on the full
    answer once the stream completes; if it fails, the `done` frame carries
    the refusal text (which may differ from what tokens already showed —
    callers should replace, not append, on `done`).
    """
    from worker.ai.chat import FINAL, TOKEN, answer_stream
    from sse_starlette.sse import EventSourceResponse
    from app.db.session import SessionLocal

    audit = db.get(Audit, audit_id)
    if not audit:
        raise HTTPException(404, "audit not found")

    session = _resolve_session(db, audit_id, body.session_id)

    user_msg = ChatMessage(session_id=session.id, role="user", content=body.message.strip(), citations=[])
    db.add(user_msg)
    db.commit()
    db.refresh(user_msg)

    history_rows = db.execute(
        select(ChatMessage)
        .where(ChatMessage.session_id == session.id)
        .order_by(ChatMessage.created_at.asc())
    ).scalars().all()

    from worker.ai.chat import ChatTurn  # local: keeps API import surface small

    history_for_llm = [
        ChatTurn(role=r.role, content=r.content)
        for r in history_rows if r.id != user_msg.id
    ]

    rows = db.execute(
        select(FindingRow).where(FindingRow.audit_id == audit_id)
    ).scalars().all()
    findings = [_row_to_finding(r) for r in rows]

    session_id = session.id
    query = body.message

    def gen():
        import json as _json

        yield {"event": "session", "data": _json.dumps({"session_id": str(session_id)})}

        if not findings:
            # Mirror the no-findings refusal path from the non-streaming route,
            # but still emit token + done so the frontend's incremental rendering
            # branch handles both shapes uniformly.
            empty_text = "This audit has no findings on file, so there's nothing for me to ground an answer in."
            yield {"event": "token", "data": _json.dumps({"text": empty_text})}
            assistant = _persist_assistant(session_id, empty_text, [])
            history_out = _load_history(session_id)
            yield {
                "event": "done",
                "data": _json.dumps({
                    "message": _msg_dict(assistant),
                    "history": [_msg_dict(m) for m in history_out],
                    "refused": False,
                }),
            }
            return

        final_result = None
        try:
            for kind, payload in answer_stream(findings, query, history=history_for_llm):
                if kind == TOKEN:
                    yield {"event": "token", "data": _json.dumps({"text": payload})}
                elif kind == FINAL:
                    final_result = payload
        except Exception as e:  # network/provider error, transport failure, etc.
            log.warning("chat stream failed: %s", type(e).__name__)
            yield {"event": "error", "data": _json.dumps({"detail": "chat stream failed"})}
            return

        if final_result is None:
            yield {"event": "error", "data": _json.dumps({"detail": "no result produced"})}
            return

        # Persist the canonical answer (possibly refusal-substituted) and emit done.
        assistant = _persist_assistant(session_id, final_result.answer, final_result.citations)
        history_out = _load_history(session_id)
        yield {
            "event": "done",
            "data": _json.dumps({
                "message": _msg_dict(assistant),
                "history": [_msg_dict(m) for m in history_out],
                "refused": bool(final_result.refused),
            }),
        }

    return EventSourceResponse(gen())


def _persist_assistant(session_id: UUID, content: str, citations: list[str]) -> ChatMessage:
    """Open a short-lived DB session to commit the assistant turn.

    We use a separate session here (not the request-scoped `db`) because the
    streaming generator runs after the FastAPI route handler returns, and the
    request session may already be closed by then.
    """
    from app.db.session import SessionLocal
    with SessionLocal() as s:
        msg = ChatMessage(
            session_id=session_id,
            role="assistant",
            content=content,
            citations=list(citations or []),
        )
        s.add(msg)
        s.commit()
        s.refresh(msg)
        return msg


def _load_history(session_id: UUID) -> list[ChatMessage]:
    from app.db.session import SessionLocal
    with SessionLocal() as s:
        return list(s.execute(
            select(ChatMessage)
            .where(ChatMessage.session_id == session_id)
            .order_by(ChatMessage.created_at.asc())
        ).scalars().all())


def _msg_dict(m: ChatMessage) -> dict:
    return {
        "id": str(m.id),
        "role": m.role,
        "content": m.content,
        "citations": list(m.citations or []),
        "created_at": m.created_at.isoformat(),
    }


@router.get("/{audit_id}/chat/{session_id}", response_model=ChatResponse)
def get_chat(audit_id: UUID, session_id: UUID, db: Session = Depends(get_db)) -> ChatResponse:
    session = db.get(ChatSession, session_id)
    if not session or session.audit_id != audit_id:
        raise HTTPException(404, "chat session not found")
    history_out = db.execute(
        select(ChatMessage)
        .where(ChatMessage.session_id == session.id)
        .order_by(ChatMessage.created_at.asc())
    ).scalars().all()
    last = history_out[-1] if history_out else None
    return ChatResponse(
        session_id=session.id,
        message=_to_out(last) if last else ChatTurnOut(
            id=uuid4(), role="assistant", content="", citations=[], created_at=session.created_at.isoformat()
        ),
        history=[_to_out(m) for m in history_out],
    )


# --- helpers ---------------------------------------------------------------


def _resolve_session(db: Session, audit_id: UUID, session_id: UUID | None) -> ChatSession:
    if session_id is not None:
        s = db.get(ChatSession, session_id)
        if s and s.audit_id == audit_id:
            return s
        raise HTTPException(404, "chat session not found")
    s = ChatSession(audit_id=audit_id)
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


def _to_out(m: ChatMessage) -> ChatTurnOut:
    return ChatTurnOut(
        id=m.id,
        role=m.role,
        content=m.content,
        citations=m.citations or [],
        created_at=m.created_at.isoformat(),
    )


def _row_to_finding(r: FindingRow):
    from audit_core import AffectedLine, Finding
    return Finding(
        id=r.id,
        audit_id=r.audit_id,
        dedupe_key=r.dedupe_key,
        title=r.title,
        severity=r.severity,
        confidence=r.confidence,
        category=r.category,
        owasp_category=r.owasp_category,
        cwe=r.cwe,
        cve=r.cve,
        affected_files=r.affected_files or [],
        affected_lines=[AffectedLine(**al) for al in (r.affected_lines or [])],
        evidence=r.evidence,
        explanation=r.explanation,
        exploitability_summary=r.exploitability_summary,
        business_impact=r.business_impact,
        safe_guidance=r.safe_guidance,
        source_tool=r.source_tool or [],
        raw_reference=r.raw_reference or {},
        epss_score=r.epss_score,
        epss_percentile=r.epss_percentile,
        kev=bool(r.kev),
        compliance=dict(getattr(r, "compliance", {}) or {}),
        reachable=getattr(r, "reachable", None),
        code_context=getattr(r, "code_context", None),
        status=r.status,
        created_at=r.created_at,
    )
