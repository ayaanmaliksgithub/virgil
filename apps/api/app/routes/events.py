"""Server-Sent Events stream of phase changes for a given audit."""
from __future__ import annotations

import asyncio
import json
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session
from sse_starlette.sse import EventSourceResponse

from app.db.models import Audit, JobEvent
from app.db.session import SessionLocal, get_db

router = APIRouter(tags=["events"])

POLL_INTERVAL_SEC = 1.5


@router.get("/v1/audits/{audit_id}/events")
async def stream_events(audit_id: UUID, db: Session = Depends(get_db)):
    audit = db.get(Audit, audit_id)
    if not audit:
        from fastapi import HTTPException
        raise HTTPException(404, "Audit not found")

    async def gen():
        last_id = 0
        # initial snapshot
        yield {"event": "phase", "data": json.dumps({"phase": audit.phase, "state": audit.state})}

        while True:
            # New session per poll to avoid stale snapshot in long-lived connection.
            with SessionLocal() as s:
                a = s.get(Audit, audit_id)
                if a is None:
                    return
                stmt = select(JobEvent).where(
                    JobEvent.audit_id == audit_id, JobEvent.id > last_id
                ).order_by(JobEvent.id.asc())
                events = s.execute(stmt).scalars().all()
                for e in events:
                    last_id = e.id
                    yield {
                        "event": "log",
                        "data": json.dumps({
                            "ts": e.ts.isoformat(),
                            "phase": e.phase,
                            "level": e.level,
                            "message": e.message,
                        }),
                    }
                if a.phase != audit.phase or a.state != audit.state:
                    yield {"event": "phase", "data": json.dumps({"phase": a.phase, "state": a.state})}
                if a.state in ("succeeded", "failed"):
                    yield {"event": "done", "data": json.dumps({"state": a.state, "phase": a.phase})}
                    return
            await asyncio.sleep(POLL_INTERVAL_SEC)

    return EventSourceResponse(gen())


# ---- Polling-friendly alternative to the SSE stream above. ---------------
# The browser EventSource path is brittle in some dev-proxy setups; this
# returns the same data via a plain JSON GET that clients can poll on a
# timer. Pass `?since=<id>` to get only newer events.

@router.get("/v1/audits/{audit_id}/events.json")
def list_events(audit_id: UUID, since: int = 0, db: Session = Depends(get_db)):
    audit = db.get(Audit, audit_id)
    if not audit:
        from fastapi import HTTPException
        raise HTTPException(404, "Audit not found")
    stmt = (
        select(JobEvent)
        .where(JobEvent.audit_id == audit_id, JobEvent.id > since)
        .order_by(JobEvent.id.asc())
    )
    rows = db.execute(stmt).scalars().all()
    return {
        "state": audit.state,
        "phase": audit.phase,
        "events": [
            {
                "id": r.id,
                "ts": r.ts.isoformat() if r.ts else None,
                "phase": r.phase,
                "level": r.level,
                "message": r.message,
            }
            for r in rows
        ],
        "cursor": rows[-1].id if rows else since,
    }
