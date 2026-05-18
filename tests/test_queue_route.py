"""Tests for the queue-position endpoint (deferred frontend item #2, backend half).

The handler is a pure read against SQLAlchemy, so we exercise it with a small
stub DB. Real-DB behavior is covered indirectly by the existing tests/api
integration suite.
"""
from __future__ import annotations

import os
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import types
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("pydantic")
pytest.importorskip("sqlalchemy")

from fastapi import HTTPException

from app.routes.audits import get_queue_status


class _StubResult:
    """Mimic the .scalar() pattern in the route handler."""
    def __init__(self, value: int):
        self._value = value
    def scalar(self) -> int:
        return self._value


class _StubDB:
    """Returns canned counts for queue queries.

    The handler issues at most two count queries (pending-ahead, in-flight). We
    pop in FIFO order so the tests can stage each invocation's return value.
    """
    def __init__(self, audit, counts: list[int]):
        self._audit = audit
        self._counts = list(counts)

    def get(self, _model, _id):
        return self._audit

    def execute(self, _stmt):
        return _StubResult(self._counts.pop(0))


def _audit(state: str, phase: str, created_at: datetime | None = None):
    return types.SimpleNamespace(
        id=uuid4(),
        state=state,
        phase=phase,
        created_at=created_at or datetime.now(timezone.utc),
    )


def test_queue_for_pending_returns_position_and_ahead():
    a = _audit("pending", "queued")
    # Order: in_flight is the SECOND query in the running branch, but for the
    # pending branch the route asks in_flight FIRST, then ahead.
    db = _StubDB(a, counts=[1, 2])  # in_flight=1, ahead=2

    out = get_queue_status(a.id, db)

    assert out["state"] == "pending"
    assert out["phase"] == "queued"
    assert out["active"] is True
    assert out["position"] == 3
    assert out["ahead"] == 2
    assert out["in_flight"] == 1


def test_queue_for_pending_with_no_audits_ahead_says_next():
    a = _audit("pending", "queued")
    db = _StubDB(a, counts=[0, 0])  # nothing in flight, nothing ahead

    out = get_queue_status(a.id, db)

    assert out["position"] == 1  # 1-indexed: position 1 means "you're next"
    assert out["ahead"] == 0


def test_queue_for_running_in_early_phase_still_active():
    a = _audit("running", "cloning")
    db = _StubDB(a, counts=[1])

    out = get_queue_status(a.id, db)

    # Running but pre-scan — UI should keep showing the queue panel.
    assert out["state"] == "running"
    assert out["active"] is True
    assert out["position"] == 0


def test_queue_for_running_in_scanning_phase_becomes_inactive():
    a = _audit("running", "scanning")
    db = _StubDB(a, counts=[1])

    out = get_queue_status(a.id, db)

    # Once scanning starts, the console stream owns the UI — banner hides.
    assert out["active"] is False


def test_queue_for_succeeded_audit_is_inactive_and_omits_position():
    a = _audit("succeeded", "completed")
    db = _StubDB(a, counts=[])

    out = get_queue_status(a.id, db)

    assert out["active"] is False
    assert "position" not in out
    assert "ahead" not in out


def test_queue_for_failed_audit_is_inactive():
    a = _audit("failed", "failed")
    db = _StubDB(a, counts=[])
    out = get_queue_status(a.id, db)
    assert out["active"] is False


def test_queue_for_missing_audit_raises_404():
    class _MissingDB:
        def get(self, _m, _id): return None

    with pytest.raises(HTTPException) as ei:
        get_queue_status(uuid4(), _MissingDB())
    assert ei.value.status_code == 404
