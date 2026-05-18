"""Outbound notifications (Phase 5 #3, #5 — minimal shape).

This is the MVP outbound surface: a single global webhook endpoint
configured via env, fired on audit completion. The full multi-tenant
version (per-org endpoints, per-event subscriptions, DB-backed delivery
log with retry/backoff) lives behind Phase 3 (orgs/teams) and will
extend this module; it's deliberately scoped down here so we ship one
useful signal without the auth model.

Email digests are intentionally NOT here yet — they need SMTP/SES
config + a scheduled job, and without orgs there's no per-user
unsubscribe target. Tracked as Phase 5 #5; will reuse `sign_payload`.

Failures never propagate out of `notify_audit_completed`. A scan that
finishes successfully must not be marked failed because a webhook
endpoint is down.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)

WEBHOOK_TIMEOUT_SEC = 10.0
SIGNATURE_HEADER = "X-Audit-Signature"
SIGNATURE_SCHEME = "sha256"


def sign_payload(secret: str, body: bytes) -> str:
    """Return the `sha256=<hex>` signature header value for `body`."""
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"{SIGNATURE_SCHEME}={mac}"


def build_audit_completed_payload(audit, findings) -> dict[str, Any]:
    """The body shape consumers will write integrations against. Keep stable.

    Severity counts let a Slack/Teams consumer render a summary without
    re-fetching. KEV count is broken out because it's the highest-signal
    "act now" cue.
    """
    sev: dict[str, int] = {}
    kev = 0
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
        if getattr(f, "kev", False):
            kev += 1
    return {
        "event": "audit.completed",
        "delivered_at": datetime.now(timezone.utc).isoformat(),
        "audit": {
            "id": str(audit.id),
            "state": audit.state,
            "source_kind": audit.source_kind,
            "source_ref": audit.source_ref,
            "finished_at": audit.finished_at.isoformat() if audit.finished_at else None,
            "baseline_audit_id": str(audit.baseline_audit_id) if audit.baseline_audit_id else None,
        },
        "summary": {
            "total_findings": len(findings),
            "severity_breakdown": sev,
            "kev_count": kev,
        },
    }


def notify_audit_completed(audit, findings) -> None:
    """POST a signed `audit.completed` payload to WEBHOOK_URL if configured.

    Best-effort: a missing URL is a no-op, a transport failure logs and
    returns, a non-2xx response logs and returns. Never raises.
    """
    url = os.environ.get("WEBHOOK_URL", "").strip()
    if not url:
        return
    secret = os.environ.get("WEBHOOK_SECRET", "").strip()
    if not secret:
        log.warning("WEBHOOK_URL set but WEBHOOK_SECRET missing — refusing to deliver unsigned")
        return

    try:
        import requests  # local import so the API container doesn't require it
    except ImportError:
        log.warning("requests not installed — webhook delivery skipped")
        return

    payload = build_audit_completed_payload(audit, findings)
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {
        "content-type": "application/json",
        SIGNATURE_HEADER: sign_payload(secret, body),
        "user-agent": "virgil-webhook/1",
    }
    try:
        res = requests.post(url, data=body, headers=headers, timeout=WEBHOOK_TIMEOUT_SEC)
    except Exception as e:  # network / DNS / TLS
        log.warning("webhook delivery to %s failed: %s", _safe_url(url), type(e).__name__)
        return
    if res.status_code >= 300:
        log.warning("webhook delivery to %s non-2xx: %d", _safe_url(url), res.status_code)


def _safe_url(url: str) -> str:
    """Don't leak query-string secrets into logs."""
    return url.split("?", 1)[0]
