"""Tests for outbound webhook delivery (Phase 5).

The HTTP path is patched so this stays a unit test — the contract under
test is the payload shape, the signature, and the no-op / no-raise
behavior when config or transport misbehaves.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import types
from datetime import datetime, timezone
from uuid import uuid4

import pytest

pytest.importorskip("pydantic")


def _audit(**over):
    base = dict(
        id=uuid4(),
        state="succeeded",
        source_kind="url",
        source_ref="https://github.com/example/repo",
        finished_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        baseline_audit_id=None,
    )
    base.update(over)
    return types.SimpleNamespace(**base)


def _f(severity: str = "High", kev: bool = False):
    return types.SimpleNamespace(severity=severity, kev=kev)


def test_payload_aggregates_severity_and_kev():
    from worker.notifications import build_audit_completed_payload

    payload = build_audit_completed_payload(
        _audit(),
        [_f("Critical", kev=True), _f("High"), _f("High"), _f("Low")],
    )
    assert payload["event"] == "audit.completed"
    assert payload["summary"]["total_findings"] == 4
    assert payload["summary"]["severity_breakdown"] == {"Critical": 1, "High": 2, "Low": 1}
    assert payload["summary"]["kev_count"] == 1


def test_signature_round_trips():
    from worker.notifications import SIGNATURE_SCHEME, sign_payload

    body = b'{"hello":"world"}'
    sig = sign_payload("topsecret", body)
    scheme, _, hexsig = sig.partition("=")
    assert scheme == SIGNATURE_SCHEME
    expected = hmac.new(b"topsecret", body, hashlib.sha256).hexdigest()
    assert hexsig == expected


def test_no_url_is_no_op(monkeypatch):
    monkeypatch.delenv("WEBHOOK_URL", raising=False)
    monkeypatch.delenv("WEBHOOK_SECRET", raising=False)

    sent: list = []
    monkeypatch.setattr("worker.notifications.os.environ", {"WEBHOOK_URL": "", "WEBHOOK_SECRET": ""})

    # Patch requests so any accidental call would be loud.
    import sys
    fake_requests = types.SimpleNamespace(post=lambda *a, **kw: sent.append((a, kw)))
    monkeypatch.setitem(sys.modules, "requests", fake_requests)

    from worker.notifications import notify_audit_completed
    notify_audit_completed(_audit(), [])
    assert sent == []


def test_url_without_secret_refuses_to_deliver(monkeypatch, caplog):
    import sys
    sent: list = []
    fake_requests = types.SimpleNamespace(post=lambda *a, **kw: sent.append((a, kw)))
    monkeypatch.setitem(sys.modules, "requests", fake_requests)
    monkeypatch.setenv("WEBHOOK_URL", "https://hooks.example.com/x")
    monkeypatch.delenv("WEBHOOK_SECRET", raising=False)

    from worker.notifications import notify_audit_completed
    notify_audit_completed(_audit(), [])
    assert sent == []  # never delivers unsigned


def test_delivery_signs_body(monkeypatch):
    import sys
    captured: dict = {}

    def fake_post(url, data=None, headers=None, timeout=None):
        captured["url"] = url
        captured["data"] = data
        captured["headers"] = headers
        captured["timeout"] = timeout
        return types.SimpleNamespace(status_code=200, text="")

    monkeypatch.setitem(sys.modules, "requests", types.SimpleNamespace(post=fake_post))
    monkeypatch.setenv("WEBHOOK_URL", "https://hooks.example.com/x")
    monkeypatch.setenv("WEBHOOK_SECRET", "shh")

    from worker.notifications import notify_audit_completed, SIGNATURE_HEADER

    notify_audit_completed(_audit(), [_f("Critical", kev=True)])
    assert captured["url"] == "https://hooks.example.com/x"
    body = captured["data"]
    sig = captured["headers"][SIGNATURE_HEADER]
    assert sig.startswith("sha256=")
    expected = hmac.new(b"shh", body, hashlib.sha256).hexdigest()
    assert sig == f"sha256={expected}"
    # body is the same json the receiver will hash
    parsed = json.loads(body)
    assert parsed["event"] == "audit.completed"
    assert parsed["summary"]["kev_count"] == 1


def test_transport_error_is_swallowed(monkeypatch):
    import sys

    def boom(*a, **kw):
        raise ConnectionError("nope")

    monkeypatch.setitem(sys.modules, "requests", types.SimpleNamespace(post=boom))
    monkeypatch.setenv("WEBHOOK_URL", "https://hooks.example.com/x")
    monkeypatch.setenv("WEBHOOK_SECRET", "shh")

    from worker.notifications import notify_audit_completed
    # Must not raise — audit success cannot depend on receiver uptime.
    notify_audit_completed(_audit(), [])


def test_non_2xx_response_is_swallowed(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "requests",
                         types.SimpleNamespace(post=lambda *a, **kw: types.SimpleNamespace(status_code=500, text="oops")))
    monkeypatch.setenv("WEBHOOK_URL", "https://hooks.example.com/x")
    monkeypatch.setenv("WEBHOOK_SECRET", "shh")

    from worker.notifications import notify_audit_completed
    notify_audit_completed(_audit(), [])  # no raise
